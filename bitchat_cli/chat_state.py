# chat_state.py
import hashlib
import json
import os
from typing import Dict, List, Set, Optional

from .identity import IdentityKeys
from .protocol import BitchatMessage


VERIFIED_PATH = os.path.expanduser("~/.bitchat/verified_peers.json")

class ChatState:
    """In-memory application state shared between the CLI and the BLE service."""
    def __init__(self, nickname: str = "", my_peer_id: Optional[bytes] = None):
        self.identity = IdentityKeys()
        if my_peer_id is None:
            self.my_peer_id = hashlib.sha256(self.identity.noise_public_key_bytes()).digest()[:8]
        else:
            self.my_peer_id = my_peer_id
        if not nickname:
            nickname = self.identity.nickname
        self.nickname = nickname
        self.messages: List[BitchatMessage] = []

        # Peers are identified by their 8-byte peer ID (hex), learned from
        # ANNOUNCE packets — NOT by BLE MAC address.
        self.peer_nicknames: Dict[str, str] = {}  # peer_id_hex -> nickname

        # Peer verification info: peer_id_hex -> {noise_pub, signing_pub}
        self.peer_info: Dict[str, dict] = {}

        # Manually verified peers (persisted to disk)
        self.verified_peers: Set[str] = set()
        self._load_verified()

        # BLE transport connections, tracked separately for link management.
        self.connected_addresses: Set[str] = set()

        # Topology (Phase 5): peer_id_hex -> set of neighbor peer_id_hex
        self.topology: Dict[str, Set[str]] = {}
        self._topology_ts: Dict[str, int] = {}  # peer_id -> last announce timestamp (ms)
        # Direct peers: peer_ids we have a direct BLE link to
        self.direct_peers: Set[str] = set()

    @property
    def my_peer_id_hex(self) -> str:
        return self.my_peer_id.hex()

    def save_nickname(self):
        """Persist the current nickname to identity.json."""
        self.identity.save_nickname(self.nickname)

    def add_message(self, message: BitchatMessage):
        self.messages.append(message)

    # --- Peer identity (from ANNOUNCE) ---
    def set_peer(self, peer_id_hex: str, nickname: str) -> bool:
        """Record/update a peer's nickname. Returns True if newly seen."""
        is_new = peer_id_hex not in self.peer_nicknames
        self.peer_nicknames[peer_id_hex] = nickname
        return is_new

    def set_peer_info(self, peer_id_hex: str, nickname: str,
                      noise_public_key: bytes, signing_public_key: bytes) -> bool:
        """Store peer verification info from ANNOUNCE. Returns True if new/changed.
        Key consistency: if peer already exists with different noise key, reject."""
        existing = self.peer_info.get(peer_id_hex)
        if existing is not None:
            # Key consistency check: reject if noise public key changed
            if existing["noise_public_key"] != noise_public_key:
                return False  # key mismatch — reject
            # Update nickname if changed
            existing["nickname"] = nickname
            self.peer_nicknames[peer_id_hex] = nickname
            return False  # already known
        # New peer
        self.peer_info[peer_id_hex] = {
            "nickname": nickname,
            "noise_public_key": noise_public_key,
            "signing_public_key": signing_public_key,
        }
        self.peer_nicknames[peer_id_hex] = nickname
        return True

    def _load_verified(self):
        try:
            with open(VERIFIED_PATH) as f:
                data = json.load(f)
            self.verified_peers = set(data.get("verified", []))
        except (FileNotFoundError, json.JSONDecodeError):
            self.verified_peers = set()

    def _save_verified(self):
        os.makedirs(os.path.dirname(VERIFIED_PATH), exist_ok=True)
        with open(VERIFIED_PATH, "w") as f:
            json.dump({"verified": sorted(self.verified_peers)}, f, indent=2)

    def is_verified(self, peer_id_hex: str) -> bool:
        return peer_id_hex in self.verified_peers

    def verify_peer(self, peer_id_hex: str) -> bool:
        """Mark a peer as verified. Returns True if successful."""
        if peer_id_hex not in self.peer_info:
            return False
        self.verified_peers.add(peer_id_hex)
        self._save_verified()
        return True

    def unverify_peer(self, peer_id_hex: str) -> bool:
        """Remove verification from a peer."""
        if peer_id_hex in self.verified_peers:
            self.verified_peers.discard(peer_id_hex)
            self._save_verified()
            return True
        return False

    def get_peer_signing_key(self, peer_id_hex: str) -> Optional[bytes]:
        info = self.peer_info.get(peer_id_hex)
        return info["signing_public_key"] if info else None

    def get_peer_noise_key(self, peer_id_hex: str) -> Optional[bytes]:
        info = self.peer_info.get(peer_id_hex)
        return info["noise_public_key"] if info else None

    def update_topology(self, peer_id_hex: str, neighbors: list, timestamp: int = 0):
        """Update topology from an incoming ANNOUNCE with TLV 0x04.

        Timestamp-gated: only updates if newer than the last recorded timestamp.
        Filters self-loops and truncates to 10 neighbors.
        """
        # Timestamp gating: ignore if not strictly newer
        prev_ts = self._topology_ts.get(peer_id_hex, 0)
        if timestamp > 0 and timestamp <= prev_ts:
            return
        if timestamp > 0:
            self._topology_ts[peer_id_hex] = timestamp
        neighbor_ids = set()
        my_id = self.my_peer_id.hex()[:16]
        for nid_bytes in neighbors[:10]:
            nid_hex = bytes(nid_bytes).hex()
            if len(nid_hex) >= 16:
                nid_hex = nid_hex[:16]
                # Filter self-loop (peer announcing itself or the CLI itself)
                if nid_hex == peer_id_hex or nid_hex == my_id:
                    continue
                neighbor_ids.add(nid_hex)
        self.topology[peer_id_hex] = neighbor_ids

    def add_direct_peer(self, peer_id_hex: str):
        self.direct_peers.add(peer_id_hex)

    def remove_direct_peer(self, peer_id_hex: str):
        self.direct_peers.discard(peer_id_hex)

    def confirmed_edges(self) -> list:
        """Return list of (peer_a, peer_b) tuples that are confirmed (bidirectional)."""
        edges = []
        seen = set()
        my_id = self.my_peer_id.hex()[:16]
        for a, neighbors in self.topology.items():
            if a == my_id:
                continue
            for b in neighbors:
                if b == my_id:
                    continue
                if b in self.topology and a in self.topology.get(b, set()):
                    key = tuple(sorted([a, b]))
                    if key not in seen:
                        seen.add(key)
                        edges.append((a, b))
        return edges

    def unconfirmed_edges(self) -> list:
        """Return list of (peer_a, peer_b) where only one side announced."""
        edges = []
        seen = set()
        my_id = self.my_peer_id.hex()[:16]
        for a, neighbors in self.topology.items():
            if a == my_id:
                continue
            for b in neighbors:
                if b == my_id:
                    continue
                if b not in self.topology or a not in self.topology.get(b, set()):
                    key = tuple(sorted([a, b]))
                    if key not in seen:
                        seen.add(key)
                        edges.append((a, b))
        return edges

    def compute_route(self, sender_hex: str, recipient_hex: str) -> list:
        """Compute a source route (intermediate hops) through confirmed edges.

        Uses BFS over confirmed edges. Returns list of intermediate peer IDs
        (excluding sender and recipient), or empty list if no path / direct.
        """
        if sender_hex == recipient_hex:
            return []
        # Build adjacency from confirmed edges
        adj = {}
        for a, b in self.confirmed_edges():
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)

        # BFS
        from collections import deque
        visited = {sender_hex}
        queue = deque([(sender_hex, [])])
        while queue:
            node, path = queue.popleft()
            for neighbor in adj.get(node, set()):
                if neighbor == recipient_hex:
                    # Found path; path contains intermediate hops so far
                    # path is from sender to node; neighbor is recipient
                    return path  # intermediate hops (node is last intermediate)
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return []  # no path found

    def remove_peer(self, peer_id_hex: str):
        self.peer_nicknames.pop(peer_id_hex, None)
        self.peer_info.pop(peer_id_hex, None)
        self.topology.pop(peer_id_hex, None)
        self._topology_ts.pop(peer_id_hex, None)
        self.direct_peers.discard(peer_id_hex)
        # Remove from other peers' neighbor sets
        for pid in list(self.topology.keys()):
            self.topology[pid].discard(peer_id_hex)

    def nickname_for(self, peer_id_hex: str) -> str:
        return self.peer_nicknames.get(peer_id_hex, peer_id_hex[:8])

    # --- BLE transport links ---
    def add_connection(self, address: str):
        self.connected_addresses.add(address)

    def remove_connection(self, address: str):
        self.connected_addresses.discard(address)
