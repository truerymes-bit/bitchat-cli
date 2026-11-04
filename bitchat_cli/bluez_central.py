# bluez_central.py
# BlueZ D-Bus based central (GATT client) for bitchat, replacing bleak.
# Uses dbus_next to talk directly to BlueZ.

import asyncio
import logging
logging.getLogger("dbus_next").setLevel(logging.CRITICAL)

class _TxPowerFilter(logging.Filter):
    def filter(self, record):
        return "TxPower" not in record.getMessage()

logging.getLogger().addFilter(_TxPowerFilter())

from dbus_next.aio import MessageBus
from dbus_next import BusType, Variant
from dbus_next.errors import DBusError
from typing import Callable, Optional, List, Dict, Any


SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

ADAPTER_PATH = "/org/bluez/hci0"


class BluezDevice:
    """Minimal device wrapper mimicking bleak's BLEDevice."""
    def __init__(self, address: str, name: str = "", rssi: int = 0):
        self.address = address
        self.name = name
        self.rssi = rssi


class BluezAdvertisement:
    """Minimal advertisement wrapper mimicking bleak's AdvertisementData."""
    def __init__(self, service_uuids: List[str] = None, rssi: int = 0):
        self.service_uuids = service_uuids or []
        self.rssi = rssi


class BluezScanner:
    """BlueZ D-Bus scanner mimicking bleak's BleakScanner."""

    def __init__(self, detection_callback: Callable, service_uuids: List[str] = None):
        self._callback = detection_callback
        self._service_uuids = [u.lower() for u in (service_uuids or [])]
        self._bus: Optional[MessageBus] = None
        self._adapter = None
        self._adapter_iface = None
        self._running = False
        self._devices: Dict[str, BluezDevice] = {}
        self._om_iface = None
        self._seen: set = set()

    async def start(self):
        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        introspection = await self._bus.introspect("org.bluez", ADAPTER_PATH)
        self._adapter = self._bus.get_proxy_object("org.bluez", ADAPTER_PATH, introspection)
        self._adapter_iface = self._adapter.get_interface("org.bluez.Adapter1")

        # Set discovery filter (optional, may not work on all adapters)
        try:
            await self._adapter_iface.call_set_discovery_filter(
                {"Transport": Variant("s", "le"), "UUIDs": Variant("as", [SERVICE_UUID])}
            )
        except Exception as e:
            logging.getLogger("bluez_central").warning(
                "UUID discovery filter not supported (%s); falling back to LE-only.", e
            )
            try:
                await self._adapter_iface.call_set_discovery_filter(
                    {"Transport": Variant("s", "le")}
                )
            except Exception as e2:
                logging.getLogger("bluez_central").warning(
                    "LE discovery filter not supported (%s); falling back to no filter.", e2
                )
                try:
                    await self._adapter_iface.call_set_discovery_filter({})
                except Exception:
                    pass

        # Listen for InterfacesAdded
        om_introspection = await self._bus.introspect("org.bluez", "/")
        om_proxy = self._bus.get_proxy_object("org.bluez", "/", om_introspection)
        self._om_iface = om_proxy.get_interface("org.freedesktop.DBus.ObjectManager")
        self._om_iface.on_interfaces_added(self._on_interfaces_added)

        # Enumerate existing devices
        await self._enumerate_devices()

        await self._adapter_iface.call_start_discovery()
        self._running = True

    async def _enumerate_devices(self):
        om_introspection = await self._bus.introspect("org.bluez", "/")
        om_proxy = self._bus.get_proxy_object("org.bluez", "/", om_introspection)
        om_iface = om_proxy.get_interface("org.freedesktop.DBus.ObjectManager")
        objects = await om_iface.call_get_managed_objects()
        for path, interfaces in objects.items():
            if "org.bluez.Device1" in interfaces:
                self._handle_device(interfaces["org.bluez.Device1"])

    def _handle_device(self, props: dict):
        addr = props.get("Address", Variant("s", "")).value
        name = props.get("Name", Variant("s", "")).value
        rssi = props.get("RSSI", Variant("n", 0)).value
        uuids = [u.lower() for u in props.get("UUIDs", Variant("as", [])).value]

        if self._service_uuids and not any(u in uuids for u in self._service_uuids):
            return

        device = BluezDevice(addr, name, rssi)
        adv = BluezAdvertisement(uuids, rssi)
        self._devices[addr] = device
        try:
            self._callback(device, adv)
        except Exception:
            pass

    def _on_interfaces_added(self, path: str, interfaces: dict):
        if not self._running:
            return
        if "org.bluez.Device1" not in interfaces:
            return
        self._handle_device(interfaces["org.bluez.Device1"])

    async def stop(self):
        self._running = False
        if self._adapter_iface:
            try:
                await self._adapter_iface.call_stop_discovery()
            except Exception:
                pass
        if self._bus:
            self._bus.disconnect()


class BluezClient:
    """BlueZ D-Bus GATT client mimicking bleak's BleakClient."""

    def __init__(self, device: BluezDevice, disconnected_callback: Optional[Callable] = None):
        self._device = device
        self.address = device.address
        self._bus: Optional[MessageBus] = None
        self._device_proxy = None
        self._device_iface = None
        self._connected = False
        self._disconnected_callback = disconnected_callback
        self._notify_callback = None
        self._char_proxy = None
        self._char_iface = None
        self._services_resolved = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self, timeout: float = 15.0):
        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        device_path = f"/org/bluez/hci0/dev_{self.address.replace(':', '_')}"
        introspection = await self._bus.introspect("org.bluez", device_path)
        self._device_proxy = self._bus.get_proxy_object("org.bluez", device_path, introspection)
        self._device_iface = self._device_proxy.get_interface("org.bluez.Device1")

        # Listen for disconnection
        props_iface = self._device_proxy.get_interface("org.freedesktop.DBus.Properties")
        props_iface.on_properties_changed(self._on_properties_changed)

        # Check if already connected
        try:
            already_connected = await self._device_iface.get_connected()
        except Exception:
            already_connected = False
        
        if not already_connected:
            await self._device_iface.call_connect()
        self._connected = True

        # Wait for services to resolve (with timeout)
        for _ in range(10):
            await asyncio.sleep(0.5)
            try:
                services_resolved = await self._device_iface.get_services_resolved()
                if services_resolved:
                    self._services_resolved = True
                    break
            except Exception:
                pass
        
        # Find the characteristic (regardless of ServicesResolved)
        await self._find_characteristic()

    async def _find_characteristic(self):
        om_introspection = await self._bus.introspect("org.bluez", "/")
        om_proxy = self._bus.get_proxy_object("org.bluez", "/", om_introspection)
        om_iface = om_proxy.get_interface("org.freedesktop.DBus.ObjectManager")
        objects = await om_iface.call_get_managed_objects()

        device_prefix = f"/org/bluez/hci0/dev_{self.address.replace(':', '_')}"
        for path, interfaces in objects.items():
            if not path.startswith(device_prefix):
                continue
            if "org.bluez.GattCharacteristic1" in interfaces:
                char_props = interfaces["org.bluez.GattCharacteristic1"]
                uuid = char_props.get("UUID", Variant("s", "")).value
                if uuid.lower() == CHARACTERISTIC_UUID.lower():
                    char_introspection = await self._bus.introspect("org.bluez", path)
                    self._char_proxy = self._bus.get_proxy_object("org.bluez", path, char_introspection)
                    self._char_iface = self._char_proxy.get_interface("org.bluez.GattCharacteristic1")
                    # Listen for notifications
                    char_props_iface = self._char_proxy.get_interface("org.freedesktop.DBus.Properties")
                    char_props_iface.on_properties_changed(self._on_char_properties_changed)
                    return

    @property
    def services(self):
        """Mimic bleak's services property. Returns list of service-like objects."""
        class Char:
            def __init__(self, uuid):
                self.uuid = uuid
        class Service:
            def __init__(self):
                self.characteristics = [Char(CHARACTERISTIC_UUID)]
        return [Service()]

    async def start_notify(self, char_uuid: str, callback: Callable):
        self._notify_callback = callback
        if self._char_iface:
            try:
                await self._char_iface.call_start_notify()
            except DBusError as e:
                if "Already" not in str(e):
                    raise

    async def write_gatt_char(self, char_uuid: str, data: bytes, response: bool = False):
        if self._char_iface:
            try:
                await self._char_iface.call_write_value(bytes(data), {})
            except Exception:
                pass

    async def disconnect(self):
        self._connected = False
        if self._device_iface:
            try:
                await self._device_iface.call_disconnect()
            except Exception:
                pass
        if self._bus:
            self._bus.disconnect()

    def _on_properties_changed(self, interface: str, changed: dict, invalidated: list):
        if interface == "org.bluez.Device1":
            if "Connected" in changed:
                connected = changed["Connected"].value
                if not connected and self._connected:
                    self._connected = False
                    if self._disconnected_callback:
                        try:
                            self._disconnected_callback(self)
                        except Exception:
                            pass

    def _on_char_properties_changed(self, interface: str, changed: dict, invalidated: list):
        if interface == "org.bluez.GattCharacteristic1":
            if "Value" in changed:
                data = bytes(changed["Value"].value)
                if self._notify_callback:
                    try:
                        self._notify_callback(self.address, bytearray(data))
                    except Exception:
                        pass