# chat_state.py
import json
import os
from typing import Dict, List, Set, Optional

from .identity import IdentityKeys
from .protocol import BitchatMessage


VERIFIED_PATH = os.path.expanduser("~/.bitchat/verified_peers.json")

class ChatState:
    """In-memory application state shared between the CLI and the BLE service."""
    def __init__(self, nickname: str, my_peer_id: bytes):
        self.nickname = nickname
        self.my_peer_id = my_peer_id              # 8 random bytes
        self.identity = IdentityKeys()
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

    @property
    def my_peer_id_hex(self) -> str:
        return self.my_peer_id.hex()

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

    def remove_peer(self, peer_id_hex: str):
        self.peer_nicknames.pop(peer_id_hex, None)
        self.peer_info.pop(peer_id_hex, None)

    def nickname_for(self, peer_id_hex: str) -> str:
        return self.peer_nicknames.get(peer_id_hex, peer_id_hex[:8])

    # --- BLE transport links ---
    def add_connection(self, address: str):
        self.connected_addresses.add(address)

    def remove_connection(self, address: str):
        self.connected_addresses.discard(address)
