# peripheral.py
#
# BLE peripheral (GATT server + advertisement) for bitchat, using BlueZ via
# bluez-peripheral.  Lets phones discover and connect to this client, so the
# link is bidirectional instead of central-only.

import asyncio
import logging

from bluez_peripheral.gatt.service import Service, ServiceCollection
from bluez_peripheral.gatt.characteristic import characteristic, CharacteristicFlags
from bluez_peripheral.util import get_message_bus, Adapter
from bluez_peripheral.agent import NoIoAgent

from .protocol import BitchatPacket
from .debuglog import dlog

from bluez_peripheral.advert import Advertisement, PacketType, AdvertisingIncludes
from dbus_next.constants import PropertyAccess
from dbus_next.service import dbus_property

SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"


class BitchatAdvertisement(Advertisement):
    """Advertisement with TxPower property defined to avoid BlueZ UnknownProperty errors."""
    @dbus_property(PropertyAccess.READWRITE)
    def TxPower(self) -> "n":  # type: ignore
        return 0  # int16, as BlueZ expects

    @TxPower.setter
    def TxPower(self, value):
        pass  # accept writes silently; BlueZ may try to set this


class BitchatPeripheral:
    """Wraps a BlueZ GATT service + advertisement for the bitchat mesh."""

    def __init__(self, nickname: str, dispatch_fn):
        self.nickname = nickname
        self.dispatch_fn = dispatch_fn
        self._bus = None
        self._char = None
        self._service = None
        self._advert = None
        self._agent = None
        self.connected_addresses: set = set()
        self._addr_last_seen: dict = {}  # addr -> monotonic timestamp

    async def start(self):
        self._bus = await get_message_bus()

        self._agent = NoIoAgent()
        await self._agent.register(self._bus)

        outer = self

        class BitchatService(Service):
            def __init__(self):
                super().__init__(SERVICE_UUID, True)

            @characteristic(CHARACTERISTIC_UUID, CharacteristicFlags.WRITE_WITHOUT_RESPONSE | CharacteristicFlags.NOTIFY)
            def bitchat_char(self, options):
                return b""

            @bitchat_char.setter
            def bitchat_char(service, data, options):
                try:
                    opts = options
                    device_path = getattr(opts, 'device', None)
                    addr = None
                    if device_path:
                        parts = str(device_path).split('/')[-1]
                        addr = parts.replace('dev_', '').replace('_', ':').upper()
                    packet = BitchatPacket.decode(bytes(data))
                    if addr is not None:
                        import time as _t
                        outer.connected_addresses.add(addr)
                        outer._addr_last_seen[addr] = _t.monotonic()
                    if packet is not None:
                        outer.dispatch_fn(packet, addr)
                except Exception as e:
                    print(f"PERIPHERAL_WRITE_ERROR: {e}", flush=True)
                    dlog(f"PERIPHERAL_WRITE_ERROR: {e}")

        self._service = BitchatService()
        await self._service.register(self._bus)

        # Grab the characteristic instance for notifications
        self._char = self._service._characteristics[0]

        self._advert = BitchatAdvertisement(
            localName=self.nickname,
            serviceUUIDs=[SERVICE_UUID],
            appearance=0,
            timeout=0,
            discoverable=True,
            packet_type=PacketType.PERIPHERAL,
            includes=AdvertisingIncludes.TX_POWER,
        )
        adapter = await Adapter.get_first(self._bus)
        await self._advert.register(self._bus, adapter)

    def notify_all(self, data: bytes):
        if self._char is not None:
            try:
                self._char.changed(data)
            except Exception:
                pass

    def cleanup_stale(self, max_age: float = 300.0):
        """Remove peripheral addresses not seen in max_age seconds."""
        import time as _t
        now = _t.monotonic()
        stale = [a for a, t in self._addr_last_seen.items() if now - t > max_age]
        for a in stale:
            self.connected_addresses.discard(a)
            self._addr_last_seen.pop(a, None)

    async def stop(self):
        if self._advert is not None:
            try:
                await self._advert.unregister() if hasattr(self._advert, "unregister") else None
            except Exception:
                pass
        if self._service is not None:
            try:
                await self._service.unregister()
            except Exception:
                pass
        if self._bus is not None:
            try:
                self._bus.disconnect()
            except Exception:
                pass