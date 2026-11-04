"""Packet ID computation for gossip sync.

Packet ID = first 16 bytes of SHA-256 over [type | senderID | timestamp | payload].
Matches the Android PacketIdUtil spec.
"""
import hashlib
from typing import Optional


def compute_packet_id(packet_type: int, sender_id: bytes, timestamp: int,
                      payload: bytes) -> bytes:
    """Return the 16-byte deterministic packet ID."""
    h = hashlib.sha256()
    h.update(bytes([packet_type]))
    h.update(sender_id[:8].ljust(8, b"\x00"))
    try:
        h.update(int(timestamp).to_bytes(8, "big"))
    except (OverflowError, ValueError, TypeError, AttributeError):
        try:
            h.update((int(timestamp) % (1 << 64)).to_bytes(8, "big"))
        except (OverflowError, ValueError, TypeError, AttributeError):
            h.update((0).to_bytes(8, "big"))
    h.update(payload)
    return h.digest()[:16]


def packet_id_from_packet(packet) -> bytes:
    """Convenience wrapper for a BitchatPacket."""
    return compute_packet_id(
        int(packet.type),
        bytes(packet.sender_id),
        int(packet.timestamp),
        bytes(packet.payload),
    )
