"""GossipSyncManager — Phase 4 GCS filter sync.

Maintains a rolling window of seen public packets (ANNOUNCE + MESSAGE),
builds GCS filters on demand, handles incoming REQUEST_SYNC by responding
with missing packets, and schedules periodic + per-peer initial syncs.

Mirrors bitchat-android GossipSyncManager for interoperability.
"""
import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple

from .packet_id import compute_packet_id, packet_id_from_packet
from .gcs_filter import (
    build_filter,
    decode_filter,
    gcs_hash,
    compute_p,
    estimate_max_elements_for_size,
)
from .request_sync import encode as encode_request_sync, decode as decode_request_sync
from ..protocol import BitchatPacket, MessageType, DEFAULT_TTL


class GossipSyncManager:
    MAX_PACKETS_PER_SYNC = 100
    MAX_FILTER_BYTES = 256
    FPR_PERCENT = 1.0
    ANNOUNCE_AGE_LIMIT_MS = 60_000  # 60 seconds
    PRUNE_INTERVAL_S = 15
    PERIODIC_INTERVAL_S = 30
    INITIAL_SYNC_DELAY_S = 5
    RESPONSE_PACE_S = 0.020  # 20 ms between response packets

    def __init__(self, state, ble_service):
        self.state = state
        self.ble = ble_service
        # packet_id hex -> packet (broadcast messages)
        self._messages: Dict[str, BitchatPacket] = {}
        # sender peer hex -> (packet_id hex, packet) (latest announce per peer)
        self._latest_announce: Dict[str, Tuple[str, BitchatPacket]] = {}
        self._running = False
        self._prune_task = None
        self._periodic_task = None
        self._initial_sync_tasks: Set[asyncio.Task] = set()
        self._response_lock = asyncio.Lock()
        self._response_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self):
        self._running = True
        self._prune_task = asyncio.ensure_future(self._prune_loop())
        self._periodic_task = asyncio.ensure_future(self._periodic_loop())

    async def stop(self):
        self._running = False
        if self._response_task is not None and not self._response_task.done():
            self._response_task.cancel()
        if self._prune_task:
            self._prune_task.cancel()
        if self._periodic_task:
            self._periodic_task.cancel()
        for t in self._initial_sync_tasks:
            t.cancel()
        self._initial_sync_tasks.clear()

    # ------------------------------------------------------------------ #
    # Recording seen packets
    # ------------------------------------------------------------------ #
    def record_packet(self, packet: BitchatPacket):
        """Record a public packet (ANNOUNCE or broadcast MESSAGE) as seen."""
        if packet.type not in (MessageType.ANNOUNCE, MessageType.MESSAGE):
            return
        if packet.type == MessageType.MESSAGE:
            rid = packet.recipient_id
            if rid is not None:
                if bytes(rid) != b"\xff" * 8:
                    return  # not broadcast
        pid = packet_id_from_packet(packet)
        pid_hex = pid.hex()

        if packet.type == MessageType.MESSAGE:
            self._messages[pid_hex] = packet
            # Enforce capacity (remove oldest)
            while len(self._messages) > self.MAX_PACKETS_PER_SYNC:
                first = next(iter(self._messages))
                del self._messages[first]
            return

        # ANNOUNCE
        now_ms = int(time.time() * 1000)
        age = now_ms - int(packet.timestamp)
        if age > self.ANNOUNCE_AGE_LIMIT_MS:
            return
        sender_hex = packet.sender_id.hex()
        old = self._latest_announce.get(sender_hex)
        if old is not None:
            old_ts = int(old[1].timestamp)
            if int(packet.timestamp) <= old_ts:
                return  # older or equal, ignore
        self._latest_announce[sender_hex] = (pid_hex, packet)
        # Enforce capacity (remove oldest)
        while len(self._latest_announce) > self.MAX_PACKETS_PER_SYNC:
            first = next(iter(self._latest_announce))
            del self._latest_announce[first]

    def remove_announcement_for_peer(self, peer_id_hex: str):
        key = peer_id_hex.lower() if isinstance(peer_id_hex, str) else peer_id_hex.hex()
        # normalize: if bytes passed
        if isinstance(peer_id_hex, (bytes, bytearray)):
            key = bytes(peer_id_hex).hex()
        else:
            key = str(peer_id_hex).lower()
        self._latest_announce.pop(key, None)
        # Remove messages from that peer
        to_remove = [
            pid for pid, pkt in self._messages.items()
            if pkt.sender_id.hex() == key
        ]
        for pid in to_remove:
            del self._messages[pid]

    # ------------------------------------------------------------------ #
    # Candidate selection / snapshot
    # ------------------------------------------------------------------ #
    def _build_candidate_list(self) -> List[Tuple[str, BitchatPacket]]:
        """Return offered (id_hex, packet) list after dependency + byte trimming."""
        cap = self.MAX_PACKETS_PER_SYNC
        fpr = self.FPR_PERCENT
        max_bytes = self.MAX_FILTER_BYTES

        candidates: List[Tuple[str, BitchatPacket]] = []
        for sender, (pid_hex, pkt) in self._latest_announce.items():
            candidates.append((pid_hex, pkt))
        for pid_hex, pkt in self._messages.items():
            candidates.append((pid_hex, pkt))

        # Stable tie-break: timestamp desc, then id asc
        candidates.sort(key=lambda x: (-int(x[1].timestamp), x[0]))

        p = compute_p(fpr)
        limit = min(cap, estimate_max_elements_for_size(max_bytes, p))

        selected: Dict[str, BitchatPacket] = {}  # preserves insertion order
        for pid_hex, packet in candidates:
            if pid_hex in selected:
                continue
            announcement = None
            if packet.type == MessageType.MESSAGE:
                sender = packet.sender_id.hex()
                ann = self._latest_announce.get(sender)
                if ann is not None:
                    ann_pid, ann_pkt = ann
                    if ann_pid not in selected:
                        announcement = (ann_pid, ann_pkt)
            required = 1 if announcement is None else 2
            if len(selected) + required > limit:
                continue
            if announcement is not None:
                selected[announcement[0]] = announcement[1]
            selected[pid_hex] = packet

        selected_list = list(selected.items())
        # Build filter (may trim further)
        id_bytes_list = [bytes.fromhex(h) for h, _ in selected_list]
        P, M, data = build_filter(id_bytes_list, max_bytes, fpr)
        encoded_count = (M >> P) if P > 0 else 0
        encoded_count = max(0, min(encoded_count, len(selected_list)))
        offered = selected_list[:encoded_count]
        return offered

    def build_filter(self) -> Tuple[int, int, bytes]:
        """Build (P, M, data) from current seen packets."""
        offered = self._build_candidate_list()
        # Rebuild filter from offered ids (matches encoded window)
        id_bytes_list = [bytes.fromhex(h) for h, _ in offered]
        if not id_bytes_list:
            p = compute_p(self.FPR_PERCENT)
            return p, (1 << p), b""
        return build_filter(id_bytes_list, self.MAX_FILTER_BYTES, self.FPR_PERCENT)

    # ------------------------------------------------------------------ #
    # Handling incoming REQUEST_SYNC
    # ------------------------------------------------------------------ #
    async def handle_request_sync(self, packet: BitchatPacket, ingress: str = None):
        result = decode_request_sync(packet.payload)
        if result is None:
            return
        P, M, data = result
        if P < 1 or P > 32:
            return
        if M <= 0:
            return
        if len(data) > 1024:
            return

        filter_values = decode_filter(P, M, data)

        offered = self._build_candidate_list()

        # Collect missing
        missing_announces = []  # (pid_hex, packet)
        missing_messages = []
        seen_announce_senders = set()

        for pid_hex, pkt in offered:
            pid_bytes = bytes.fromhex(pid_hex)
            v = gcs_hash(pid_bytes) % M
            if v == 0:
                v = 1
            if v in filter_values:
                continue  # requester has it
            if pkt.type == MessageType.ANNOUNCE:
                sender = pkt.sender_id.hex()
                if sender in seen_announce_senders:
                    continue
                seen_announce_senders.add(sender)
                missing_announces.append((pid_hex, pkt))
            elif pkt.type == MessageType.MESSAGE:
                missing_messages.append((pid_hex, pkt))

        # Sort messages by ascending timestamp, then packet id
        missing_messages.sort(key=lambda x: (int(x[1].timestamp), x[0]))

        # Announces then messages; announces sorted by timestamp too
        missing_announces.sort(key=lambda x: (int(x[1].timestamp), x[0]))

        to_send = [p for (_, p) in (missing_announces + missing_messages)]

        if self._response_lock.locked():
            return
        async with self._response_lock:
            self._response_task = asyncio.current_task()
            try:
                for i, pkt in enumerate(to_send):
                    if not self._running:
                        return
                    if i > 0:
                        await asyncio.sleep(self.RESPONSE_PACE_S)
                    resp = BitchatPacket(
                        type=pkt.type,
                        sender_id=pkt.sender_id,
                        recipient_id=pkt.recipient_id,
                        timestamp=pkt.timestamp,
                        payload=pkt.payload,
                        signature=pkt.signature,
                        ttl=0,
                        version=pkt.version,
                    )
                    encoded = resp.encode()
                    if ingress is not None:
                        await self.ble._send_to_address(ingress, encoded)
                    else:
                        await self.ble._broadcast_raw(encoded)
            except asyncio.CancelledError:
                raise
            finally:
                self._response_task = None

    # ------------------------------------------------------------------ #
    # Sending sync requests
    # ------------------------------------------------------------------ #
    async def send_periodic_sync(self):
        if not self.ble.clients and self.ble._peripheral is None:
            return
        P, M, data = self.build_filter()
        payload = encode_request_sync(P, M, data)
        packet = BitchatPacket(
            type=MessageType.REQUEST_SYNC,
            sender_id=self.state.my_peer_id,
            recipient_id=None,
            payload=payload,
            ttl=0,
        )
        encoded = packet.encode()
        await self.ble._broadcast_raw(encoded)

    def schedule_initial_sync(self, peer_id_hex: str):
        async def _delayed():
            await asyncio.sleep(self.INITIAL_SYNC_DELAY_S)
            if not self._running:
                return
            P, M, data = self.build_filter()
            payload = encode_request_sync(P, M, data)
            packet = BitchatPacket(
                type=MessageType.REQUEST_SYNC,
                sender_id=self.state.my_peer_id,
                recipient_id=bytes.fromhex(peer_id_hex),
                payload=payload,
                ttl=0,
            )
            encoded = packet.encode()
            await self.ble._broadcast_raw(encoded)

        task = asyncio.ensure_future(_delayed())
        self._initial_sync_tasks.add(task)
        task.add_done_callback(self._initial_sync_tasks.discard)

    # ------------------------------------------------------------------ #
    # Pruning
    # ------------------------------------------------------------------ #
    async def _prune_loop(self):
        while self._running:
            await asyncio.sleep(self.PRUNE_INTERVAL_S)
            self._prune()

    def _prune(self):
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - self.ANNOUNCE_AGE_LIMIT_MS
        to_remove = []
        for peer, (pid, pkt) in self._latest_announce.items():
            if int(pkt.timestamp) < cutoff:
                to_remove.append(peer)
        for peer in to_remove:
            self.remove_announcement_for_peer(peer)

    async def _periodic_loop(self):
        while self._running:
            await asyncio.sleep(self.PERIODIC_INTERVAL_S)
            try:
                await self.send_periodic_sync()
            except Exception:
                pass
