# ble_service.py
#
# BLE transport for bitchat. Runs BlueZ as a BLE *central*: it scans for
# devices advertising the bitchat service UUID, connects, subscribes to the
# bitchat characteristic for notifications, and writes packets to it.
#
# Scope: public (broadcast) chat only. We announce ourselves and sign every
# packet (the real app drops unsigned public messages), parse inbound announce/
# message/leave/fragment packets, and ignore Noise (private) traffic.
#
# Note: central role via BlueZ D-Bus + peripheral role via bluez-peripheral (BlueZ).
# This client can now advertise as a peripheral, so phones can connect to it.

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Optional

import logging
logging.getLogger("dbus_next").setLevel(logging.CRITICAL)
logging.getLogger("bluez_peripheral").setLevel(logging.CRITICAL)

class _TxPowerFilter(logging.Filter):
    def filter(self, record):
        return "TxPower" not in record.getMessage()

import builtins
_orig_print = builtins.print
def _quiet_print(*args, **kwargs):
    msg = " ".join(str(a) for a in args)
    if "TxPower" in msg or "Unrecognised exception" in msg or "UnknownProperty" in msg:
        return
    _orig_print(*args, **kwargs)
builtins.print = _quiet_print
logging.getLogger().addFilter(_TxPowerFilter())

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from noise.connection import NoiseConnection, Keypair

from .bluez_central import BluezScanner as BleakScanner, BluezClient as BleakClient, BluezDevice as BLEDevice
from .bluez_central import BluezAdvertisement as AdvertisementData
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import ANSI

from . import theme
from .debuglog import dlog
from .chat_state import ChatState
from .media import (
    BitchatFilePacket,
    MAX_PAYLOAD_BYTES,
    category_for_mime,
    extension_for_mime,
    message_prefix,
    mime_for_extension,
)
from .protocol import (
    AnnouncementPacket,
    BitchatMessage,
    BitchatPacket,
    DEFAULT_TTL,
    FragmentReassembler,
    MessageType,
)
from .peripheral import BitchatPeripheral
from .sync.gossip_sync import GossipSyncManager

# Real bitchat UUIDs (mainnet). Lower-cased to compare against advertisement data.
SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

CONNECTION_TIMEOUT = 15.0       # seconds for a single connect attempt
MAX_CONNECT_ATTEMPTS = 3        # before a device is permanently ignored
RETRY_COOLDOWN = 15.0           # seconds to wait before re-attempting a device
ANNOUNCE_INTERVAL = 30.0        # seconds between periodic re-announces
MAX_FRAME_SIZE = 480            # bytes before a packet is fragmented for BLE
FRAGMENT_PACING = 0.020         # seconds between BLE writes when sending a fragment train

# Where received media (images, voice notes, files) is saved.
DOWNLOAD_DIR = Path.home() / ".bitchat" / "downloads"
SEEN_PATH = Path.home() / ".bitchat" / "seen_packets.json"
DM_SESSION_MAX_AGE = 15.0     # seconds before a DM triggers a fresh handshake
HS_RETRY_INTERVAL = 10.0      # seconds between background handshake retries
HS_RETRY_MAX = 6              # max background retries per peer
WRITE_RETRIES = 3             # retries for a BLE write that fails with 'In Progress'
WRITE_RETRY_DELAY = 0.05      # seconds between those retries
DM_ACK_TIMEOUT = 10.0         # seconds before retrying an unacked DM
DM_ACK_MAX_RETRIES = 3        # max retries per DM
DM_HANDSHAKE_TIMEOUT = 8.0    # seconds to wait for that handshake to finish


def _hs_debug(msg: str) -> None:
    """Debug: print and append a handshake trace line to the debug log."""
    print(msg, flush=True)
    dlog(msg)

class NoiseSession:
    """Manages a Noise_XX handshake and transport encryption with one peer."""
    def __init__(self, our_noise_priv: bytes, peer_noise_pub: bytes, is_initiator: bool):
        self.our_noise_priv = our_noise_priv
        self.peer_noise_pub = peer_noise_pub
        self.is_initiator = is_initiator
        self.conn = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_SHA256')
        if is_initiator:
            self.conn.set_as_initiator()
        else:
            self.conn.set_as_responder()
        self.conn.set_keypair_from_private_bytes(Keypair.STATIC, our_noise_priv)
        self.conn.start_handshake()
        self._send_key = None
        self._recv_key = None
        self._send_counter = 0
        self._recv_window = set()  # simplified: track seen counters
        self._last_error = None
        self.created_at = time.monotonic()

    @property
    def is_finished(self) -> bool:
        return self.conn.handshake_finished

    def _extract_transport_keys(self):
        """Extract transport keys from cipher states after handshake."""
        if self._send_key is None and self.conn.handshake_finished:
            self._send_key = self.conn.noise_protocol.cipher_state_encrypt.k
            self._recv_key = self.conn.noise_protocol.cipher_state_decrypt.k

    def start_handshake(self) -> bytes:
        """Initiator: produce first handshake message. Returns bytes to send."""
        if self.is_initiator:
            msg = self.conn.write_message(b'')
            return bytes(msg)
        return b''

    def handle_handshake_message(self, data: bytes) -> Optional[bytes]:
        """Process incoming handshake message. Returns response bytes to send, or None."""
        try:
            if self.is_initiator:
                self.conn.read_message(data)
                if not self.conn.handshake_finished:
                    msg = self.conn.write_message(b'')
                    return bytes(msg)
                self._extract_transport_keys()
                return None
            else:
                self.conn.read_message(data)
                if not self.conn.handshake_finished:
                    msg = self.conn.write_message(b'')
                    return bytes(msg)
                self._extract_transport_keys()
                return None
        except Exception as e:
            self._last_error = str(e) or type(e).__name__
            return None

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.is_finished:
            raise RuntimeError("Handshake not finished")
        self._extract_transport_keys()
        # bitchat transport frame: 4-byte BE nonce ‖ ciphertext ‖ 16-byte tag
        counter = self._send_counter
        self._send_counter += 1
        nonce_bytes = counter.to_bytes(4, 'big')  # only low 32 bits carried
        # Full nonce: 00000000 ‖ LE64(counter)
        full_nonce = b'\x00' * 4 + counter.to_bytes(8, 'little')
        cipher = ChaCha20Poly1305(self._send_key)
        ct = cipher.encrypt(full_nonce, plaintext, None)  # includes 16-byte tag
        # Frame: 4-byte BE counter + ciphertext (which includes tag)
        return nonce_bytes + ct

    def decrypt(self, data: bytes) -> bytes:
        if not self.is_finished:
            raise RuntimeError("Handshake not finished")
        self._extract_transport_keys()
        if len(data) < 4 + 16:
            raise ValueError("Frame too short")
        counter = int.from_bytes(data[:4], 'big')
        # Replay protection: reject already-seen counters
        if counter in self._recv_window:
            raise ValueError("Replayed frame")
        ct = data[4:]  # ciphertext + tag
        # Full nonce: 00000000 ‖ LE64(counter)
        full_nonce = b'\x00' * 4 + counter.to_bytes(8, 'little')
        cipher = ChaCha20Poly1305(self._recv_key)
        result = cipher.decrypt(full_nonce, ct, None)
        self._recv_window.add(counter)
        # Bound the window
        if len(self._recv_window) > 1000:
            # Keep only the most recent 500
            sorted_counters = sorted(self._recv_window)
            self._recv_window = set(sorted_counters[-500:])
        return result


class BLEService:
    """Central-role BLE transport speaking the real bitchat public-chat protocol."""

    def __init__(self, state: ChatState, cli_redraw_callback):
        self.state = state
        self.cli_redraw = cli_redraw_callback
        self.clients: Dict[str, BleakClient] = {}      # BLE address -> client
        self._connecting: Set[str] = set()
        self._write_locks: Dict[str, asyncio.Lock] = {}  # BLE address -> write lock
        self._ignored: Set[str] = set()                # confirmed non-peers / dead
        self._ignored_peers: Set[str] = set()          # peer IDs confirmed non-peers / dead (from scan response)
        self._pending_acks: Dict[str, dict] = {}      # msg_id -> {peer_id, content, time, retries}
        self._attempts: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}
        self._reassembler = FragmentReassembler()
        self._scanner: BleakScanner = None
        self._running = False
        self._peripheral = None
        self._noise_sessions: Dict[str, NoiseSession] = {}   # peer_id_hex -> session
        self._sync_manager: Optional[GossipSyncManager] = None
        # Map BLE address -> peer_id_hex for direct peers, for cleanup on drop
        self._direct_addr_to_peer: Dict[str, str] = {}
        self._peer_addr: Dict[str, str] = {}  # peer_id_hex -> BLE address
        # Capacity-bounded seen-set (LRU) for packet dedup, persisted to disk.
        from collections import OrderedDict
        import threading
        import json
        self._seen_packets = OrderedDict()
        self._relayed_fragments = set()
        self._dedup_lock = threading.Lock()
        self._SEEN_CAP = 2000
        # Load persisted seen packets from disk (restart survival)
        try:
            with open(SEEN_PATH) as f:
                data = json.load(f)
            for pid_hex in data.get("seen", []):
                try:
                    pid_bytes = bytes.fromhex(pid_hex)
                except (ValueError, TypeError):
                    continue
                if len(pid_bytes) != 16:
                    continue
                self._seen_packets[pid_bytes] = None
            # Trim to capacity (oldest first)
            while len(self._seen_packets) > self._SEEN_CAP:
                self._seen_packets.popitem(last=False)
        except (FileNotFoundError, json.JSONDecodeError, OSError, AttributeError, TypeError):
            pass

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def run(self):
        """Start scanning and keep re-announcing while connected."""
        self._running = True
        # Start peripheral (advertisement + GATT server) so phones can connect to us
        try:
            self._peripheral = BitchatPeripheral(
                nickname=getattr(self.state, 'nickname', 'bitchat'),
                dispatch_fn=self._dispatch,
            )
            await self._peripheral.start()
            self._sys("Advertising as bitchat peer (BlueZ peripheral)…")
        except Exception as e:
            self._err(f"Peripheral start failed: {e}")
            self._peripheral = None
        self._scanner = BleakScanner(
            detection_callback=self._on_detection, service_uuids=[SERVICE_UUID]
        )
        try:
            await self._scanner.start()
        except Exception as e:
            self._err(f"Could not start Bluetooth scan: {e}. "
                      f"Check that a Bluetooth adapter is present and enabled.")
            return
        self._sys("Scanning for bitchat peers over Bluetooth…")

        # Start gossip sync manager (Phase 4)
        self._sync_manager = GossipSyncManager(self.state, self)
        # Transfer persisted seen packets to sync manager
        with self._dedup_lock:
            self._sync_manager._seen_packet_ids = set(self._seen_packets.keys())
        await self._sync_manager.start()
        self._hs_retry_task = asyncio.ensure_future(self._handshake_retry_loop())
        self._dm_ack_task = asyncio.ensure_future(self._dm_ack_retry_loop())

        try:
            while self._running:
                await asyncio.sleep(ANNOUNCE_INTERVAL)
                # Clean up stale peripheral addresses
                if self._peripheral is not None:
                    self._peripheral.cleanup_stale(300.0)
                if self.clients:
                    await self.send_announce()
        except asyncio.CancelledError:
            raise

    async def _handshake_retry_loop(self):
        """Retry Noise handshakes that never finished (lost msg1/msg2 on a dropped link).

        Every HS_RETRY_INTERVAL seconds, for each known peer whose session is missing
        or unfinished for longer than HS_RETRY_INTERVAL, start a new handshake.
        Gives up on a peer after HS_RETRY_MAX attempts (reset once it finishes).
        """
        attempts: Dict[str, int] = {}
        try:
            while self._running:
                await asyncio.sleep(HS_RETRY_INTERVAL)
                linked = bool(self.clients) or bool(
                    self._peripheral is not None and self._peripheral.connected_addresses)
                if not linked:
                    continue
                my_id = self.state.my_peer_id.hex()
                for pid in list(self.state.peer_info.keys()):
                    if pid == my_id:
                        continue
                    sess = self._noise_sessions.get(pid)
                    if sess is not None and sess.is_finished:
                        attempts.pop(pid, None)
                        continue
                    if sess is not None and (time.monotonic() - sess.created_at) < HS_RETRY_INTERVAL:
                        continue  # handshake still in progress
                    if attempts.get(pid, 0) >= HS_RETRY_MAX:
                        continue
                    pub = self.state.get_peer_noise_key(pid)
                    if pub is None:
                        continue
                    attempts[pid] = attempts.get(pid, 0) + 1
                    dlog(f"HS_RETRY: peer={pid[:8]} attempt={attempts[pid]}")
                    self._initiate_noise_handshake(pid, pub)
        except asyncio.CancelledError:
            raise

    async def _dm_ack_retry_loop(self):
        """Retry DMs that have not received a delivery ack."""
        try:
            while self._running:
                await asyncio.sleep(5.0)
                now = time.monotonic()
                to_retry = []
                for msg_id in list(self._pending_acks.keys()):
                    info = self._pending_acks.get(msg_id)
                    if info is None:
                        continue
                    if now - info["time"] < DM_ACK_TIMEOUT:
                        continue
                    if info["retries"] >= DM_ACK_MAX_RETRIES:
                        self._warn(f"DM delivery failed (no ack): {msg_id[:8]}")
                        del self._pending_acks[msg_id]
                        continue
                    to_retry.append((msg_id, info))
                for msg_id, info in to_retry:
                    info["retries"] += 1
                    info["time"] = now
                    dlog(f"DM_RETRY: msg_id={msg_id[:8]} attempt={info['retries']}")
                    try:
                        await self.send_private_message(info["peer_id"], info["content"])
                    except Exception as e:
                        dlog(f"DM_RETRY failed: {e}")
        except asyncio.CancelledError:
            raise

    async def stop(self):
        self._running = False
        _t = getattr(self, "_hs_retry_task", None)
        if _t is not None:
            _t.cancel()
        _t2 = getattr(self, "_dm_ack_task", None)
        if _t2 is not None:
            _t2.cancel()
        try:
            if self.clients:
                await self.send_leave()
        except Exception:
            pass
        if self._peripheral is not None:
            try:
                await self._peripheral.stop()
            except Exception:
                pass
            self._peripheral = None
        if self._sync_manager is not None:
            try:
                await self._sync_manager.stop()
            except Exception:
                pass
            # Persist seen packets to disk before clearing
            try:
                import json
                SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
                with self._dedup_lock:
                    seen_ids = list(self._seen_packets.keys())
                with open(SEEN_PATH, "w") as f:
                    json.dump({"seen": [p.hex() for p in seen_ids]}, f)
            except (OSError, AttributeError, TypeError, ValueError):
                pass
            self._sync_manager = None
        if self._scanner is not None:
            try:
                await self._scanner.stop()
            except Exception:
                pass
        disconnects = [
            c.disconnect() for c in list(self.clients.values()) if c.is_connected
        ]
        if disconnects:
            await asyncio.gather(*disconnects, return_exceptions=True)

    # ------------------------------------------------------------------ #
    # Discovery & connection (the fix for the "connect to everything" storm)
    # ------------------------------------------------------------------ #
    def _on_detection(self, device: BLEDevice, adv: AdvertisementData):
        if not self._running:
            return
        addr = device.address.upper()
        if addr in self.clients or addr in self._connecting or addr in self._ignored:
            return
        # Android phones include their peer ID in the scan response (first 8
        # bytes of service data) so scanners can deduplicate by peer ID even
        # when the advertising MAC rotates.  Use it to avoid treating a rotated
        # address as a new device.
        peer_id_hex = None
        sd = (getattr(adv, "service_data", None) or {}).get(SERVICE_UUID)
        if sd and len(sd) >= 8:
            peer_id_hex = sd[:8].hex()
        if peer_id_hex is not None:
            if peer_id_hex in self._ignored_peers:
                self._ignored.add(addr)
                return
            if peer_id_hex in self._noise_sessions:
                self._ignored.add(addr)
                return
        if time.monotonic() < self._cooldown_until.get(addr, 0.0):
            return
        # Only connect to devices actually advertising the bitchat service.
        advertised = [u.lower() for u in (adv.service_uuids or [])]
        if SERVICE_UUID not in advertised:
            return
        self._connecting.add(addr)
        asyncio.create_task(self._connect(device, peer_id_hex))

    async def _connect(self, device: BLEDevice, peer_id_hex: Optional[str] = None):
        addr = device.address.upper()
        attempts = self._attempts.get(addr, 0) + 1
        self._attempts[addr] = attempts
        client = BleakClient(device, disconnected_callback=self._on_disconnect)
        try:
            await asyncio.wait_for(client.connect(), timeout=CONNECTION_TIMEOUT)

            if not self._has_characteristic(client):
                self._sys(f"{addr} is not a bitchat peer; ignoring.")
                self._ignored.add(addr)
                if peer_id_hex is not None:
                    self._ignored_peers.add(peer_id_hex)
                await client.disconnect()
                return

            self.clients[addr] = client
            self.state.add_connection(addr)
            await client.start_notify(CHARACTERISTIC_UUID, self._on_notify)
            self._ok(f"Connected to a bitchat peer ({addr}).")
            await self.send_announce()  # introduce ourselves so they list us
        except Exception as e:  # noqa: BLE001 - never let a connect kill the loop
            reason = "timed out" if isinstance(e, asyncio.TimeoutError) else str(e)
            self._fail_device(addr, reason)
            if peer_id_hex is not None:
                self._ignored_peers.add(peer_id_hex)
            await self._safe_disconnect(client)
        finally:
            self._connecting.discard(addr)

    def _fail_device(self, addr: str, reason: str):
        if self._attempts.get(addr, 0) >= MAX_CONNECT_ATTEMPTS:
            self._warn(f"Giving up on {addr} after {MAX_CONNECT_ATTEMPTS} attempts ({reason}).")
            self._ignored.add(addr)
            # Prevent unbounded growth over long-running sessions.
            if len(self._ignored) > 500:
                self._ignored.clear()
                self._ignored_peers.clear()
        else:
            self._cooldown_until[addr] = time.monotonic() + RETRY_COOLDOWN

    @staticmethod
    def _has_characteristic(client: BleakClient) -> bool:
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == CHARACTERISTIC_UUID:
                    return True
        return False

    @staticmethod
    async def _safe_disconnect(client: BleakClient):
        try:
            if client.is_connected:
                await client.disconnect()
        except Exception:
            pass

    def _on_disconnect(self, client: BleakClient):
        addr = client.address.upper()
        self.clients.pop(addr, None)
        self._connecting.discard(addr)
        if addr in self.state.connected_addresses:
            self.state.remove_connection(addr)
            self._leave(f"Disconnected from {addr}")
        # Clean up direct-peer tracking for this address
        peer_id = self._direct_addr_to_peer.pop(addr, None)
        if peer_id is not None:
            self.state.remove_direct_peer(peer_id)
        # Clean up Noise sessions for peers on this address
        # (sessions are keyed by peer_id, not address, so we can't easily
        #  map address->peer_id here; sessions will be cleaned up on re-announce)
        # Disconnect cooldown
        self._cooldown_until[addr] = time.monotonic() + 30.0

    # ------------------------------------------------------------------ #
    # Inbound packet handling
    # ------------------------------------------------------------------ #
    def _on_notify(self, addr, data: bytearray):
        packet = BitchatPacket.decode(bytes(data))
        if packet is not None:
            self._dispatch(packet, addr)
        else:
            pass

    def _dispatch(self, packet: BitchatPacket, ingress: str = None):
        if packet.sender_id == self.state.my_peer_id:
            return  # our own packet relayed back to us

        # Dedup check
        import hashlib
        pid = hashlib.sha256()
        pid.update(bytes([packet.type]))
        pid.update(packet.sender_id)
        try:
            pid.update(packet.timestamp.to_bytes(8, 'big'))
        except (OverflowError, ValueError, TypeError, AttributeError):
            try:
                pid.update((int(packet.timestamp) % (1 << 64)).to_bytes(8, 'big'))
            except (OverflowError, ValueError, TypeError, AttributeError):
                pid.update((0).to_bytes(8, 'big'))
        pid.update(packet.payload)
        packet_id = pid.digest()[:16]

        # Capacity-bounded seen-set (no time-based expiry).  Uses an
        # OrderedDict as an LRU set: keys are packet IDs, values are None.
        # Thread-safe via _dedup_lock.  Also consults the sync manager's
        # seen set for public packets so both paths share one source of truth.
        with self._dedup_lock:
            if packet_id in self._seen_packets:
                return  # duplicate, drop
            # Also check sync manager's seen set for public packets
            if self._sync_manager is not None and packet.type in (MessageType.ANNOUNCE, MessageType.MESSAGE):
                if packet_id in getattr(self._sync_manager, '_seen_packet_ids', set()):
                    return  # already known via sync
            # Evict oldest if at capacity
            if len(self._seen_packets) >= self._SEEN_CAP:
                self._seen_packets.popitem(last=False)
            self._seen_packets[packet_id] = None
        # Record in sync manager's seen set for public packets
        if self._sync_manager is not None and packet.type in (MessageType.ANNOUNCE, MessageType.MESSAGE):
            if not hasattr(self._sync_manager, '_seen_packet_ids'):
                self._sync_manager._seen_packet_ids = set()
            self._sync_manager._seen_packet_ids.add(packet_id)

        if packet.type == MessageType.FRAGMENT:
            if packet.ttl > 1:
                self._schedule_relay(packet, ingress, packet_id)
                # Track fragment_id so the reassembled inner packet is not re-relayed.
                # Fragment payload: fragment_id(8) + index(2) + total(2) + type(1) + chunk
                if len(packet.payload) >= 13:
                    frag_id = packet.payload[:8]
                    key = (bytes(packet.sender_id), frag_id)
                    self._relayed_fragments.add(key)
                    # Bound the set
                    if len(self._relayed_fragments) > 1000:
                        self._relayed_fragments.clear()
            inner = self._reassembler.add(packet)
            if inner is not None:
                frag_key = self._reassembler.last_key
                reassembled = BitchatPacket.decode(inner)
                if reassembled is not None:
                    # Check if this specific fragment train was already relayed
                    if frag_key in self._relayed_fragments:
                        self._dispatch_no_relay(reassembled, ingress)
                        self._relayed_fragments.discard(frag_key)
                    else:
                        self._dispatch(reassembled, ingress)
            return

        # Handle Noise handshake packets
        if packet.type == MessageType.NOISE_HANDSHAKE:
            peer_id = packet.sender_id.hex()
            _s = self._noise_sessions.get(peer_id)
            _hs_debug(f"HS_RECV: from={peer_id[:8]} to={packet.recipient_id.hex()[:8] if packet.recipient_id else None} len={len(packet.payload)} ttl={packet.ttl} session={'none' if _s is None else ('finished' if _s.is_finished else ('initiator' if _s.is_initiator else 'responder'))}")
            # Check if this is for us
            if packet.recipient_id is not None and packet.recipient_id != self.state.my_peer_id:
                _hs_debug("HS_DROP: not for us")
                return  # not for us
            # Get peer's noise public key
            peer_noise_pub = self.state.get_peer_noise_key(peer_id)
            if peer_noise_pub is None:
                _hs_debug("HS_DROP: unknown peer noise key")
                return  # unknown peer, drop
            # Drop duplicate handshake frames (same peer + first 16 payload bytes),
            # matching Android SecurityManager's processedKeyExchanges check.
            from collections import OrderedDict
            if not hasattr(self, "_seen_handshakes"):
                self._seen_handshakes = OrderedDict()
            hs_key = (peer_id, bytes(packet.payload[:16]))
            if hs_key in self._seen_handshakes:
                _hs_debug("HS_DROP: duplicate")
                return
            self._seen_handshakes[hs_key] = None
            while len(self._seen_handshakes) > 500:
                self._seen_handshakes.popitem(last=False)
            session = self._noise_sessions.get(peer_id)
            if session is None:
                # Create as responder
                our_noise_priv = self.state.identity.noise_private_key_bytes()
                session = NoiseSession(our_noise_priv, peer_noise_pub, is_initiator=False)
                self._noise_sessions[peer_id] = session
            elif len(packet.payload) == 32 and (session.is_finished or session.is_initiator):
                # Phone is initiating (msg1). Replace session if:
                # - finished (phone restarted, new handshake) — Android replaces established sessions
                # - initiator collision (yield to responder)
                if session.is_finished:
                    self._sys(f"Replacing finished Noise session with {peer_id[:8]} (phone restarted)")
                our_noise_priv = self.state.identity.noise_private_key_bytes()
                session = NoiseSession(our_noise_priv, peer_noise_pub, is_initiator=False)
                self._noise_sessions[peer_id] = session
            # Handle the handshake message
            response = session.handle_handshake_message(packet.payload)
            if getattr(session, '_last_error', None):
                self._sys(f"Noise handshake error with {peer_id[:8]}: {session._last_error}")
                session._last_error = None
                self._noise_sessions.pop(peer_id, None)
                return
            _hs_debug(f"HS_RESULT: peer={peer_id[:8]} response_len={len(response) if response else 0} finished={session.is_finished}")
            if response:
                # Send response
                resp_packet = self._sign(BitchatPacket(
                    type=MessageType.NOISE_HANDSHAKE,
                    sender_id=self.state.my_peer_id,
                    recipient_id=packet.sender_id,
                    payload=response,
                    ttl=DEFAULT_TTL,
                ))
                asyncio.ensure_future(self._broadcast(resp_packet))
            if session.is_finished:
                self._sys(f"Noise handshake complete with {peer_id[:8]}")
            return

        # Handle Noise encrypted messages
        if packet.type == MessageType.NOISE_ENCRYPTED:
            peer_id = packet.sender_id.hex()
            if packet.recipient_id is not None and packet.recipient_id != self.state.my_peer_id:
                return  # not for us
            session = self._noise_sessions.get(peer_id)
            if session is None or not session.is_finished:
                return  # no session or handshake not complete
            try:
                plaintext = session.decrypt(packet.payload)
                # Parse NoisePayload: type byte + data
                if len(plaintext) < 2:
                    return
                noise_type = plaintext[0]
                if noise_type == 0x03:  # DELIVERED ack
                    ack_msg_id = plaintext[1:].decode('utf-8', errors='replace')
                    dlog(f"DM_ACK_RECV: from={peer_id[:8]} msg_id={ack_msg_id}")
                    self._pending_acks.pop(ack_msg_id, None)
                    self._ok(f"DM delivered: {ack_msg_id[:8]}")
                    return
                if noise_type != 0x01:  # PRIVATE_MESSAGE only
                    return
                # Parse PrivateMessagePacket TLV from plaintext[1:]
                data = plaintext[1:]
                msg_id = None
                content = None
                offset = 0
                while offset + 2 <= len(data):
                    tlv_type = data[offset]
                    tlv_len = data[offset + 1]
                    offset += 2
                    if offset + tlv_len > len(data):
                        break
                    val = data[offset:offset + tlv_len]
                    offset += tlv_len
                    if tlv_type == 0x00:
                        msg_id = val.decode('utf-8', errors='replace')
                    elif tlv_type == 0x01:
                        content = val.decode('utf-8', errors='replace')
                if content is None:
                    return
                sender = self.state.nickname_for(peer_id)
                display = content.strip() if content.strip() else "(empty)"
                self.state.add_message(
                    BitchatMessage(content=display, sender=sender, timestamp=packet.timestamp)
                )
                self._chat(f"[DM] {sender}", display, ts_ms=packet.timestamp)
                # Send delivery ACK back, mirroring Android's sendDeliveryAck.
                if msg_id is not None:
                    asyncio.ensure_future(self._send_delivery_ack(peer_id, msg_id))
                return

            except Exception as e:
                print(f"DM_RECV_ERROR: {e}", flush=True)
                dlog(f"DM_RECV_ERROR: {e}")
            return
        # Handle gossip sync requests (Phase 4)
        if packet.type == MessageType.REQUEST_SYNC:
            if self._sync_manager is not None:
                asyncio.ensure_future(self._sync_manager.handle_request_sync(packet, ingress))
            return

        signed_types = (MessageType.ANNOUNCE, MessageType.MESSAGE,
                        MessageType.LEAVE, MessageType.FILE_TRANSFER)
        if packet.type in signed_types:
            peer_id = packet.sender_id.hex()
            # Need signing key from peer's ANNOUNCE
            signing_key_bytes = self.state.get_peer_signing_key(peer_id)
            if signing_key_bytes is None:
                # For ANNOUNCE, we can't verify (no prior key) — allow first ANNOUNCE
                if packet.type != MessageType.ANNOUNCE:
                    # No ANNOUNCE received yet — cannot verify, drop
                    return
            else:
                if not self._verify_signature(packet, signing_key_bytes):
                    # Invalid signature — drop
                    return

        if packet.type == MessageType.ANNOUNCE:
            self._handle_announce(packet, ingress)
        elif packet.type == MessageType.MESSAGE:
            self._handle_message(packet)
        elif packet.type == MessageType.LEAVE:
            self._handle_leave(packet)
        elif packet.type == MessageType.FILE_TRANSFER:
            self._handle_file(packet)

        # Log unhandled packet types
        known_types = (MessageType.ANNOUNCE, MessageType.MESSAGE, MessageType.LEAVE,
                       MessageType.NOISE_HANDSHAKE, MessageType.NOISE_ENCRYPTED,
                       MessageType.FRAGMENT, MessageType.FILE_TRANSFER)
        if packet.type not in known_types:
            pass

        # Record public packets for gossip sync (Phase 4)
        if self._sync_manager is not None and packet.type in (MessageType.ANNOUNCE, MessageType.MESSAGE):
            self._sync_manager.record_packet(packet)

        # Relay (skip if this packet is addressed to us — we are the final destination)
        if packet.ttl > 1 and packet.recipient_id != self.state.my_peer_id:
            self._schedule_relay(packet, ingress, packet_id)

    def _dispatch_no_relay(self, packet: BitchatPacket, ingress: str = None):
        """Dispatch a packet but skip the relay step (fragments already relayed)."""
        # Temporarily set ttl to 0 to prevent relay, then restore
        orig_ttl = packet.ttl
        packet.ttl = 0
        self._dispatch(packet, ingress)
        packet.ttl = orig_ttl

    def _schedule_relay(self, packet: BitchatPacket, ingress: str = None, packet_id: bytes = None):
        relay_packet = BitchatPacket(
            type=packet.type,
            sender_id=packet.sender_id,
            recipient_id=packet.recipient_id,
            timestamp=packet.timestamp,
            payload=packet.payload,
            signature=packet.signature,
            ttl=packet.ttl - 1,
            version=packet.version,
            route=packet.route,
        )
        peers = [a for a in self.clients.keys() if a != ingress and self.clients[a].is_connected]
        if not peers:
            return
        if packet.type == MessageType.MESSAGE:
            import random
            degree = len(peers)
            fanout_count = max(1, degree.bit_length())
            fanout_count = min(fanout_count, degree)
            seed = hash(packet_id or (bytes(packet.sender_id) + packet.payload)) & 0xFFFFFFFF
            rng = random.Random(seed)
            rng.shuffle(peers)
            peers = peers[:fanout_count]
        # Source routing (v2): if packet has a route and we're in it,
        # unicast to the next hop instead of flooding.
        use_unicast = False
        unicast_addr = None
        if packet.route and packet.version >= 2 and packet.recipient_id is not None:
            my_id = bytes(self.state.my_peer_id)
            route = [bytes(h) for h in packet.route]
            idx = None
            for i, hop in enumerate(route):
                if hop == my_id:
                    idx = i
                    break
            if idx is not None:
                # Determine next hop
                if idx + 1 < len(route):
                    next_hop_id = route[idx + 1].hex()
                else:
                    next_hop_id = bytes(packet.recipient_id).hex()
                # Look up BLE address for next hop
                addr = self._peer_addr.get(next_hop_id)
                if addr and addr in self.clients and self.clients[addr].is_connected:
                    use_unicast = True
                    unicast_addr = addr

        if use_unicast and unicast_addr:
            # Unicast to next hop only
            asyncio.ensure_future(self._unicast_after_delay(relay_packet, unicast_addr, 0.010))
        else:
            import random as _r
            jitter = _r.uniform(0.010, 0.220)
            asyncio.ensure_future(self._relay_after_delay(relay_packet, peers, jitter))

    async def _relay_after_delay(self, packet: BitchatPacket, peers: list, delay: float):
        await asyncio.sleep(delay)
        encoded = packet.encode()
        fragmented = len(encoded) > MAX_FRAME_SIZE
        frames = self._fragment(encoded, packet.type, packet.version, getattr(packet, 'route', None)) if fragmented else [encoded]
        for frame in frames:
            for addr in peers:
                client = self.clients.get(addr)
                if client and client.is_connected:
                    try:
                        await client.write_gatt_char(CHARACTERISTIC_UUID, frame, response=False)
                    except Exception:
                        pass
            if self._peripheral is not None:
                try:
                    self._peripheral.notify_all(frame)
                except Exception:
                    pass
            if fragmented:
                await asyncio.sleep(FRAGMENT_PACING)

    async def _unicast_after_delay(self, packet: BitchatPacket, addr: str, delay: float):
        await asyncio.sleep(delay)
        encoded = packet.encode()
        fragmented = len(encoded) > MAX_FRAME_SIZE
        frames = self._fragment(encoded, packet.type, packet.version, packet.route) if fragmented else [encoded]
        client = self.clients.get(addr)
        for frame in frames:
            if client and client.is_connected:
                try:
                    await client.write_gatt_char(CHARACTERISTIC_UUID, frame, response=False)
                except Exception:
                    pass
            if self._peripheral is not None:
                try:
                    self._peripheral.notify_all(frame)
                except Exception:
                    pass
            if fragmented:
                await asyncio.sleep(FRAGMENT_PACING)

    def _verify_signature(self, packet: BitchatPacket, signing_key_bytes: bytes) -> bool:
        """Verify Ed25519 signature on a packet. Returns True if valid."""
        if packet.signature is None:
            return False
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(signing_key_bytes)
            pub_key.verify(packet.signature, packet.data_for_signing())
            return True
        except (InvalidSignature, Exception):
            return False

    def _initiate_noise_handshake(self, peer_id_hex: str, peer_noise_pub: bytes):
        """Create a Noise session and send the first handshake message."""
        our_noise_priv = self.state.identity.noise_private_key_bytes()
        try:
            session = NoiseSession(our_noise_priv, peer_noise_pub, is_initiator=True)
            self._noise_sessions[peer_id_hex] = session
            msg = session.start_handshake()
            if msg:
                packet = self._sign(BitchatPacket(
                    type=MessageType.NOISE_HANDSHAKE,
                    sender_id=self.state.my_peer_id,
                    recipient_id=bytes.fromhex(peer_id_hex),
                    payload=msg,
                    ttl=DEFAULT_TTL,
                ))
                asyncio.ensure_future(self._broadcast(packet))
        except Exception:
            pass

    def _handle_announce(self, packet: BitchatPacket, ingress: str = None):
        ann = AnnouncementPacket.decode(packet.payload)
        if ann is None:
            return
        peer_id = packet.sender_id.hex()
        # Store peer verification info (key consistency check)
        is_new = self.state.set_peer_info(
            peer_id, ann.nickname, ann.noise_public_key, ann.signing_public_key,
            capabilities=getattr(ann, "capabilities", 0),
        )
        # Phase 5: update topology from direct neighbors TLV (even if empty)
        # Gating: only update topology for verified peers or first announce (TOFU).
        # Subsequent announces from unverified peers don't change topology.
        is_verified = self.state.is_verified(peer_id)
        if is_new or is_verified:
            self.state.update_topology(peer_id, ann.direct_neighbors or [], timestamp=packet.timestamp)
        # Track peer -> BLE address mapping (for source routing unicast)
        if ingress is not None:
            self._peer_addr[peer_id] = ingress

        # Track as direct peer only if received over a direct BLE link.
        # Require a first-hop announce (ttl == DEFAULT_TTL): relayed or
        # gossip-synced announces (ttl < DEFAULT_TTL / ttl == 0) must not
        # promote a peer to direct, otherwise multi-hop peers get falsely
        # marked as direct links.
        is_direct = False
        if ingress is not None and packet.ttl == DEFAULT_TTL:
            if ingress in self.clients:
                is_direct = True
            elif self._peripheral is not None and ingress in self._peripheral.connected_addresses:
                is_direct = True
        if is_direct:
            self.state.add_direct_peer(peer_id)
            self._direct_addr_to_peer[ingress] = peer_id
            # Send announce immediately so peer sees us as a direct neighbor
            asyncio.ensure_future(self.send_announce())
        if is_new:
            # Warn if a peer with the same nickname but different identity appears
            for existing_pid, existing_nick in self.state.peer_nicknames.items():
                if existing_pid != peer_id and existing_nick == ann.nickname:
                    verified_note = " (was verified)" if self.state.is_verified(existing_pid) else ""
                    self._warn(
                        f"Peer '{ann.nickname}' appeared with a new identity "
                        f"({existing_pid[:8]} → {peer_id[:8]}){verified_note} — "
                        f"verify fingerprint before trusting"
                    )
                    break
            self._join(f"{ann.nickname} is now online")
            # Create Noise session and initiate handshake
            if peer_id not in self._noise_sessions:
                self._initiate_noise_handshake(peer_id, ann.noise_public_key)
            # Schedule initial gossip sync with new peer (Phase 4)
            if self._sync_manager is not None:
                self._sync_manager.schedule_initial_sync(peer_id)
        else:
            # Check if key mismatch caused rejection
            existing_noise = self.state.get_peer_noise_key(peer_id)
            if existing_noise is not None and existing_noise != ann.noise_public_key:
                self._warn(f"Peer {peer_id[:8]} key mismatch — rejected")
                return

    def _handle_message(self, packet: BitchatPacket):
        try:
            content = packet.payload.decode("utf-8")
        except UnicodeDecodeError:
            return
        peer_id = packet.sender_id.hex()
        sender = self.state.nickname_for(peer_id)
        self.state.add_message(
            BitchatMessage(content=content, sender=sender, timestamp=packet.timestamp)
        )
        self._chat(sender, content, ts_ms=packet.timestamp)

    def _handle_leave(self, packet: BitchatPacket):
        peer_id = packet.sender_id.hex()
        nickname = self.state.nickname_for(peer_id)
        self.state.remove_peer(peer_id)
        self.state.remove_direct_peer(peer_id)
        self._peer_addr.pop(peer_id, None)
        if self._sync_manager is not None:
            try:
                self._sync_manager.remove_announcement_for_peer(peer_id)
            except Exception:
                pass
        self._leave(f"{nickname} went offline")

    def _handle_file(self, packet: BitchatPacket):
        """Decode a received FILE_TRANSFER payload, save it to disk, auto-open."""
        fp = BitchatFilePacket.decode(packet.payload)
        if fp is None:
            return
        category = category_for_mime(fp.mime_type)
        filename = self._safe_filename(fp.file_name, fp.mime_type)
        try:
            DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
            path = DOWNLOAD_DIR / filename
            path.write_bytes(fp.content)
        except OSError as e:  # noqa: BLE001
            self._warn(f"Failed to save received media: {e}")
            return

        peer_id = packet.sender_id.hex()
        sender = self.state.nickname_for(peer_id)
        content = f"{message_prefix(category)}{filename}"
        self.state.add_message(
            BitchatMessage(content=content, sender=sender, timestamp=packet.timestamp)
        )
        self._media(sender, category, filename, path=path, ts_ms=packet.timestamp)
        self._open_file(path)

    @staticmethod
    def _safe_filename(name, mime) -> str:
        """A safe basename for a received file (no path traversal)."""
        base = os.path.basename(name) if name else ""
        base = base.replace("\x00", "").strip().lstrip(".")
        if not base or base in ("", "."):
            ext = extension_for_mime(mime)
            base = f"{int(time.time() * 1000)}.{ext}"
        return base

    def _open_file(self, path: Path):
        """Best-effort, non-blocking open with the OS default viewer."""
        try:
            if sys.platform == "darwin":
                cmd = ["open", str(path)]
            elif sys.platform.startswith("win"):
                cmd = ["cmd", "/c", "start", "", str(path)]
            else:
                cmd = ["xdg-open", str(path)]
            subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:  # noqa: BLE001 - opener missing/unavailable is non-fatal
            pass

    # ------------------------------------------------------------------ #
    # Outbound packets
    # ------------------------------------------------------------------ #
    def _sign(self, packet: BitchatPacket) -> BitchatPacket:
        packet.signature = self.state.identity.sign(packet.data_for_signing())
        return packet

    async def send_announce(self):
        direct_neighbor_ids = []
        for pid in self.state.direct_peers:
            try:
                direct_neighbor_ids.append(bytes.fromhex(pid))
            except (ValueError, TypeError):
                pass
        ann = AnnouncementPacket(
            nickname=self.state.nickname,
            noise_public_key=self.state.identity.noise_public_key_bytes(),
            signing_public_key=self.state.identity.signing_public_key_bytes(),
            direct_neighbors=direct_neighbor_ids,
        )
        payload = ann.encode()
        if payload is None:
            return
        packet = self._sign(BitchatPacket(
            type=MessageType.ANNOUNCE, sender_id=self.state.my_peer_id,
            recipient_id=None, payload=payload, ttl=DEFAULT_TTL,
        ))
        await self._broadcast(packet)
        if self._sync_manager is not None:
            self._sync_manager.record_packet(packet)

    async def send_public_message(self, content: str) -> BitchatMessage:
        packet = self._sign(BitchatPacket(
            type=MessageType.MESSAGE, sender_id=self.state.my_peer_id,
            recipient_id=None, payload=content.encode("utf-8"), ttl=DEFAULT_TTL,
        ))
        await self._broadcast(packet)
        if self._sync_manager is not None:
            self._sync_manager.record_packet(packet)
        message = BitchatMessage(content=content, sender=self.state.nickname)
        self.state.add_message(message)
        self._chat(self.state.nickname, content, is_self=True)
        return message

    async def send_routed_message(self, recipient_hex: str, content: str):
        """Send a message to a specific recipient via source routing.

        Computes a route through confirmed edges. If no route is found,
        falls back to normal broadcast (flood).
        """
        recipient_bytes = bytes.fromhex(recipient_hex)
        route_ids = self.state.compute_route(self.state.my_peer_id.hex(), recipient_hex)
        if route_ids is None:
            route_bytes = None
        else:
            route_bytes = [bytes.fromhex(h) for h in route_ids]
        packet = self._sign(BitchatPacket(
            type=MessageType.MESSAGE,
            sender_id=self.state.my_peer_id,
            recipient_id=recipient_bytes,
            payload=content.encode("utf-8"),
            ttl=DEFAULT_TTL,
            version=2,
            route=route_bytes,
        ))
        # Delivery: unicast to first hop (if routed) or direct recipient,
        # falling back to broadcast (flood) when neither is an outbound
        # connection we can write to.
        unicast_addr = None
        if route_ids:  # non-empty route
            first_hop = route_ids[0]
            addr = self._peer_addr.get(first_hop)
            if addr and addr in self.clients and self.clients[addr].is_connected:
                unicast_addr = addr
        if unicast_addr is None:
            addr = self._peer_addr.get(recipient_hex)
            if addr and addr in self.clients and self.clients[addr].is_connected:
                unicast_addr = addr

        sent = False
        if unicast_addr is not None:
            encoded = packet.encode()
            fragmented = len(encoded) > MAX_FRAME_SIZE
            frames = self._fragment(encoded, packet.type, packet.version, packet.route) if fragmented else [encoded]
            client = self.clients.get(unicast_addr)
            ok = True
            for frame in frames:
                if client and client.is_connected:
                    try:
                        await client.write_gatt_char(CHARACTERISTIC_UUID, frame, response=False)
                    except Exception:
                        ok = False
                        break
                else:
                    ok = False
                    break
                if fragmented:
                    await asyncio.sleep(FRAGMENT_PACING)
            if ok:
                sent = True
        if not sent:
            await self._broadcast(packet)
        if self._sync_manager is not None:
            self._sync_manager.record_packet(packet)
        if route_ids is None:
            self._sys("No route found - broadcasting (flood).")
        elif route_ids:
            hops = " -> ".join([self.state.my_peer_id.hex()[:8]] + [h[:8] for h in route_ids] + [recipient_hex[:8]])
            self._sys(f"Routed via: {hops}")
        else:
            self._sys("Direct peer - broadcasting.")
        message = BitchatMessage(content=content, sender=self.state.nickname)
        self.state.add_message(message)
        self._chat(self.state.nickname, content, is_self=True)
        return message

    async def _send_delivery_ack(self, recipient_peer_id: str, message_id: str):
        """Send a DELIVERED ack, mirroring Android's sendDeliveryAck."""
        session = self._noise_sessions.get(recipient_peer_id)
        if session is None or not session.is_finished:
            return
        try:
            ack_payload = bytes([0x03]) + message_id.encode('utf-8')
            ciphertext = session.encrypt(ack_payload)
            packet = self._sign(BitchatPacket(
                type=MessageType.NOISE_ENCRYPTED,
                sender_id=self.state.my_peer_id,
                recipient_id=bytes.fromhex(recipient_peer_id),
                payload=ciphertext,
                ttl=DEFAULT_TTL,
            ))
            await self._broadcast(packet)
            dlog(f"DM_ACK_SEND: to={recipient_peer_id[:8]} msg_id={message_id}")
        except Exception as e:
            dlog(f"DM_ACK_SEND failed: {e}")

    async def send_private_message(self, peer_id_hex: str, content: str):
        """Send an encrypted private message to a peer."""
        session = self._noise_sessions.get(peer_id_hex)
        # Phones drop their Noise session when their BLE link to us drops and we
        # are not told.  Re-handshake first if the session is missing, unfinished,
        # or older than DM_SESSION_MAX_AGE seconds.
        if (session is None or not session.is_finished
                or (time.monotonic() - session.created_at) > DM_SESSION_MAX_AGE):
            peer_noise_pub = self.state.get_peer_noise_key(peer_id_hex)
            if peer_noise_pub is None:
                self._warn(f"DM not sent: no Noise key known for {peer_id_hex[:8]}.")
                return
            self._initiate_noise_handshake(peer_id_hex, peer_noise_pub)
            deadline = time.monotonic() + DM_HANDSHAKE_TIMEOUT
            while time.monotonic() < deadline:
                session = self._noise_sessions.get(peer_id_hex)
                if session is not None and session.is_finished:
                    break
                await asyncio.sleep(0.1)
            session = self._noise_sessions.get(peer_id_hex)
            if session is None or not session.is_finished:
                self._warn(f"DM not sent: handshake with {peer_id_hex[:8]} failed.")
                return
            # The phone may have dropped the peer (and its nickname) when its link
            # to us went down.  Re-announce now so the phone has our nickname before
            # the DM arrives (otherwise the sender shows as 'Unknown').
            await self.send_announce()
            await asyncio.sleep(0.2)
        try:
            import uuid
            msg_id = str(uuid.uuid4()).upper()
            content_bytes = content.encode('utf-8')
            if len(content_bytes) > 255:
                self._warn(f"DM content too long ({len(content_bytes)} bytes > 255) — not sent.")
                return
            # Build NoisePayload: type byte 0x01 (PRIVATE_MESSAGE) + PrivateMessagePacket TLV
            # TLV: [0x00][len][msg_id][0x01][len][content]
            msg_id_bytes = msg_id.encode('utf-8')
            tlv = bytes([0x00, len(msg_id_bytes)]) + msg_id_bytes + bytes([0x01, len(content_bytes)]) + content_bytes
            plaintext = bytes([0x01]) + tlv
            ciphertext = session.encrypt(plaintext)
            packet = self._sign(BitchatPacket(
                type=MessageType.NOISE_ENCRYPTED,
                sender_id=self.state.my_peer_id,
                recipient_id=bytes.fromhex(peer_id_hex),
                payload=ciphertext,
                ttl=DEFAULT_TTL,  # match Android: encrypted DMs use TTL 7 so other peers relay them
            ))
            print(f"DM_SEND: sender={self.state.my_peer_id.hex()} recipient={peer_id_hex} ttl={DEFAULT_TTL}", flush=True)
            dlog(f"DM_SEND: sender={self.state.my_peer_id.hex()} recipient={peer_id_hex} ttl={DEFAULT_TTL}")
            await self._broadcast(packet)
            self._pending_acks[msg_id] = {"peer_id": peer_id_hex, "content": content, "time": time.monotonic(), "retries": 0}
            self._chat(f"[DM to {peer_id_hex[:8]}]", content, is_self=True)
        except Exception as e:
            self._warn(f"Failed to send private message: {e}")

    async def send_leave(self):
        packet = self._sign(BitchatPacket(
            type=MessageType.LEAVE, sender_id=self.state.my_peer_id,
            recipient_id=None, payload=self.state.nickname.encode("utf-8"),
            ttl=DEFAULT_TTL,
        ))
        await self._broadcast(packet)

    async def send_file(self, path: str):
        self._sys("File transfer is currently disabled.")
        return
        payload = fp.encode()
        if payload is None:
            self._warn(f"'{p.name}' could not be encoded for transfer. Not sent.")
            return

        has_peers = bool(self.clients) or (self._peripheral is not None and bool(self._peripheral.connected_addresses))
        if not has_peers:
            self._warn(f"No peers connected yet — '{p.name}' not sent. "
                       f"Wait until a peer is online, then try again.")
            return

        packet = self._sign(BitchatPacket(
            type=MessageType.FILE_TRANSFER, sender_id=self.state.my_peer_id,
            recipient_id=None, payload=payload, ttl=DEFAULT_TTL, version=2,
        ))
        kib = len(content) / 1024
        self._sys(f"Sending {p.name} ({kib:.0f} KiB) — large files take a few seconds…")
        await self._broadcast(packet)

        content_str = f"{message_prefix(category)}{p.name}"
        self.state.add_message(
            BitchatMessage(content=content_str, sender=self.state.nickname)
        )
        self._media(self.state.nickname, category, f"{p.name} ({len(content)} bytes)",
                    is_self=True)

    async def _write_frame(self, addr: str, client, frame: bytes):
        """Write one frame to a link: serialized per link, retrying BlueZ 'In Progress'.

        'In Progress' means a previous operation on the link is still pending, so it is
        transient.  Any other error (or retries exhausted) is raised to the caller.
        """
        lock = self._write_locks.setdefault(addr, asyncio.Lock())
        async with lock:
            for attempt in range(WRITE_RETRIES + 1):
                try:
                    await client.write_gatt_char(CHARACTERISTIC_UUID, frame, response=False)
                    return
                except Exception as e:  # noqa: BLE001
                    if "In Progress" in str(e) and attempt < WRITE_RETRIES:
                        dlog(f"WRITE_RETRY: addr={addr} attempt={attempt + 1}")
                        await asyncio.sleep(WRITE_RETRY_DELAY)
                        continue
                    raise

    async def _broadcast(self, packet: BitchatPacket):
        encoded = packet.encode()
        fragmented = len(encoded) > MAX_FRAME_SIZE
        frames = self._fragment(encoded, packet.type, packet.version, packet.route) if fragmented else [encoded]
        failed = []  # (addr, reason) of links to tear down after this pass
        for addr, client in list(self.clients.items()):
            if not client.is_connected:
                failed.append((addr, "link down"))
                continue
            for frame in frames:
                try:
                    await self._write_frame(addr, client, frame)
                except Exception as e:  # noqa: BLE001
                    # A write error (e.g. BlueZ stale characteristic) means the
                    # link is dead even if is_connected still reports True. Drop
                    # it once rather than retrying on every message/announce.
                    failed.append((addr, str(e)))
                    break
                # Pace long fragment trains so the peer's BLE buffers can drain.
                if fragmented:
                    await asyncio.sleep(FRAGMENT_PACING)
        for addr, reason in failed:
            await self._drop_client(addr, reason)
        # Also notify subscribed centrals via peripheral role
        if self._peripheral is not None:
            for frame in frames:
                self._peripheral.notify_all(frame)

    async def _broadcast_raw(self, data: bytes):
        """Send pre-encoded bytes to all connected clients + peripheral."""
        for addr, client in list(self.clients.items()):
            if not client.is_connected:
                continue
            try:
                await client.write_gatt_char(CHARACTERISTIC_UUID, data, response=False)
            except Exception:
                pass
        if self._peripheral is not None:
            try:
                self._peripheral.notify_all(data)
            except Exception:
                pass

    async def _send_to_address(self, addr: str, data: bytes):
        """Send pre-encoded bytes to a single client by BLE address."""
        client = self.clients.get(addr)
        if client is not None and client.is_connected:
            try:
                await client.write_gatt_char(CHARACTERISTIC_UUID, data, response=False)
            except Exception:
                pass

    async def _drop_client(self, addr: str, reason: str = ""):
        """Tear down a dead link and let the scanner reconnect later."""
        client = self.clients.pop(addr, None)
        self._write_locks.pop(addr, None)
        if client is None:
            return
        self.state.remove_connection(addr)
        # Extended cooldown: don't reconnect to this addr for 30s
        # This prevents tight reconnect loops and lets the scanner find other peers
        self._cooldown_until[addr] = time.monotonic() + 30.0
        self._leave(f"Lost connection to {addr}" + (f" ({reason})" if reason else ""))
        await self._safe_disconnect(client)

    def _fragment(self, encoded_packet: bytes, original_type: int, version: int = 1, route: list = None) -> List[bytes]:
        """Split an oversized encoded packet into FRAGMENT packets."""
        fragment_id = os.urandom(8)
        chunk_size = MAX_FRAME_SIZE - 40  # room for fragment + packet headers
        chunks = [encoded_packet[i:i + chunk_size]
                  for i in range(0, len(encoded_packet), chunk_size)]
        total = len(chunks)
        frames = []
        for index, chunk in enumerate(chunks):
            payload = (fragment_id + index.to_bytes(2, "big") + total.to_bytes(2, "big")
                       + bytes([int(original_type)]) + chunk)
            frag = BitchatPacket(
                type=MessageType.FRAGMENT, sender_id=self.state.my_peer_id,
                recipient_id=None, payload=payload, ttl=DEFAULT_TTL,
                version=version, route=route,
            )
            # Encode WITHOUT padding: PKCS#7 padding would round a ~475-byte
            # fragment up to a 512-byte block, which can exceed the negotiated
            # ATT MTU on a write-without-response and be silently dropped. The
            # receiver parses by explicit payload length, so padding is optional.
            frames.append(frag.encode(padding=False))
        return frames

    # ------------------------------------------------------------------ #
    # Output helpers — all chat/system output flows through here so the
    # styling (see theme.py) stays consistent and the prompt is redrawn.
    # ------------------------------------------------------------------ #
    def _emit(self, line: str):
        # Under prompt_toolkit's patch_stdout(), a plain print() of raw ANSI
        # escapes is rendered literally; print_formatted_text(ANSI(...)) parses
        # the codes and renders them correctly above the live prompt.
        print_formatted_text(ANSI(line))
        self.cli_redraw()

    def _sys(self, msg: str):
        dlog(f"SYS {msg}")
        self._emit(theme.system(msg))

    def _ok(self, msg: str):
        dlog(f"OK {msg}")
        self._emit(theme.ok(msg))

    def _warn(self, msg: str):
        dlog(f"WARN {msg}")
        self._emit(theme.warn(msg))

    def _err(self, msg: str):
        dlog(f"ERR {msg}")
        self._emit(theme.error(msg))

    def _join(self, msg: str):
        dlog(f"JOIN {msg}")
        self._emit(theme.join(msg))

    def _leave(self, msg: str):
        dlog(f"LEAVE {msg}")
        self._emit(theme.leave(msg))

    def _chat(self, sender: str, content: str, ts_ms=None, is_self: bool = False):
        self._emit(theme.chat(sender, content, ts_ms=ts_ms, is_self=is_self))

    def _media(self, sender: str, category: str, label: str, path=None,
               ts_ms=None, is_self: bool = False):
        self._emit(theme.media(sender, category, label, path=path,
                               ts_ms=ts_ms, is_self=is_self))
