# protocol.py
#
# Binary wire protocol for bitchat, matching the real app
# (https://github.com/permissionlesstech/bitchat) closely enough to interoperate
# for PUBLIC (broadcast) chat. Private/Noise-encrypted messages are NOT handled.
#
# Packet layout (protocol version 1, all multi-byte values big-endian):
#
#   version(1) type(1) ttl(1) timestamp_ms(8) flags(1) payloadLen(2)
#   senderID(8) [recipientID(8) if flag HAS_RECIPIENT] payload[payloadLen]
#   [signature(64) if flag HAS_SIGNATURE]
#   ... then PKCS#7 padding to the next block size (256/512/1024/2048).
#
# This module is pure data + serialization; it performs no I/O.

import struct
import time
import uuid
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

# --- Constants ---
VERSION = 1
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64
V1_HEADER_SIZE = 14  # version..payloadLen, before senderID
V2_HEADER_SIZE = 16
DEFAULT_TTL = 7
BROADCAST_RECIPIENT = b"\xff" * RECIPIENT_ID_SIZE

# Standard padding block sizes (must match MessagePadding.swift).
BLOCK_SIZES = (256, 512, 1024, 2048)


class MessageType(IntEnum):
    """Packet-level message types (matches the real app's MessageType.swift)."""
    ANNOUNCE = 0x01          # "I'm here" with nickname + public keys
    MESSAGE = 0x02           # Public chat message (unencrypted)
    LEAVE = 0x03             # "I'm leaving"
    NOISE_HANDSHAKE = 0x10   # Noise handshake (unhandled here)
    NOISE_ENCRYPTED = 0x11   # Encrypted private payload (unhandled here)
    FRAGMENT = 0x20          # A fragment of a larger packet
    REQUEST_SYNC = 0x21      # Gossip sync request (unhandled here)
    FILE_TRANSFER = 0x22     # Binary file payload (unhandled here)


class PacketFlags:
    HAS_RECIPIENT = 0x01
    HAS_SIGNATURE = 0x02
    IS_COMPRESSED = 0x04
    HAS_ROUTE = 0x08  # v2+ only


# --------------------------------------------------------------------------- #
# Padding (PKCS#7-style to a standard block size)
# --------------------------------------------------------------------------- #
class MessagePadding:
    @staticmethod
    def optimal_block_size(data_size: int) -> int:
        # Account for a little overhead, then pick the smallest block that fits.
        total = data_size + 16
        for block in BLOCK_SIZES:
            if total <= block:
                return block
        return data_size  # too big for a block; will be fragmented anyway

    @staticmethod
    def pad(data: bytes, target_size: int) -> bytes:
        if len(data) >= target_size:
            return data
        needed = target_size - len(data)
        if needed <= 0 or needed > 255:
            return data  # pad length must fit in one byte
        return data + bytes([needed]) * needed

    @staticmethod
    def unpad(data: bytes) -> bytes:
        if not data:
            return data
        pad_len = data[-1]
        if pad_len == 0 or pad_len > len(data):
            return data
        # Verify every trailing byte equals the pad length (PKCS#7).
        if any(b != pad_len for b in data[-pad_len:]):
            return data
        return data[:-pad_len]


COMPRESSION_THRESHOLD = 100  # matches Android AppConstants.COMPRESSION_THRESHOLD_BYTES


def _should_compress(data: bytes) -> bool:
    """Same heuristic as Android CompressionUtil.shouldCompress."""
    if len(data) < COMPRESSION_THRESHOLD:
        return False
    return len(set(data)) / min(len(data), 256) < 0.9


def _deflate_raw(data: bytes) -> Optional[bytes]:
    """Raw DEFLATE at default level (like Java Deflater(DEFAULT, nowrap=True))."""
    c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    out = c.compress(data) + c.flush()
    return out if 0 < len(out) < len(data) else None


def _decompress(compressed: bytes, original_size: int) -> Optional[bytes]:
    """Decompress an inbound payload. Apple's zlib produces raw DEFLATE."""
    for wbits in (-15, 15):
        try:
            out = zlib.decompress(compressed, wbits)
            if len(out) == original_size:
                return out
        except zlib.error:
            continue
    return None


# --------------------------------------------------------------------------- #
# BitchatPacket
# --------------------------------------------------------------------------- #
@dataclass
class BitchatPacket:
    """A single frame on the bitchat network."""
    type: int = MessageType.MESSAGE
    sender_id: bytes = b"\x00" * SENDER_ID_SIZE
    recipient_id: Optional[bytes] = None
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    payload: bytes = b""
    signature: Optional[bytes] = None
    ttl: int = DEFAULT_TTL
    version: int = VERSION
    route: Optional[List[bytes]] = None  # Source route: intermediate hops (v2 only)

    def encode(self, padding: bool = True) -> bytes:
        """Serialize to the binary wire format. We never compress on send.

        Version 1 carries a 2-byte payload length (max 65535 bytes); version 2
        carries a 4-byte length, required for large payloads such as file
        transfers (images/voice/files can be up to 1 MiB). This mirrors upstream,
        which sends FILE_TRANSFER packets as version 2.
        """
        flags = 0
        if self.recipient_id is not None:
            flags |= PacketFlags.HAS_RECIPIENT
        if self.signature is not None:
            flags |= PacketFlags.HAS_SIGNATURE
        if self.route and self.version >= 2 and self.recipient_id is not None:
            flags |= PacketFlags.HAS_ROUTE

        # Mirror Android: compress FILE_TRANSFER payloads (>=100 bytes, <90% unique
        # bytes) with raw DEFLATE, prefixed by the original size. Android verifies
        # the signature over its own compressed re-encode, so we must send (and
        # sign) the compressed form too.
        wire_payload = self.payload
        if (int(self.type) == MessageType.FILE_TRANSFER and self.version >= 2
                and _should_compress(self.payload)):
            comp = _deflate_raw(self.payload)
            if comp is not None:
                flags |= PacketFlags.IS_COMPRESSED
                wire_payload = len(self.payload).to_bytes(4, "big") + comp

        sender = self.sender_id[:SENDER_ID_SIZE].ljust(SENDER_ID_SIZE, b"\x00")
        payload_len = len(wire_payload)

        if self.version >= 2:
            data = struct.pack(
                ">BBBQB", self.version, int(self.type), self.ttl,
                self.timestamp & 0xFFFFFFFFFFFFFFFF, flags,
            )
            data += payload_len.to_bytes(4, "big")
        else:
            if payload_len > 0xFFFF:
                raise ValueError(
                    f"payload of {payload_len} bytes exceeds the version-1 limit "
                    f"(65535 bytes); use version=2 for large payloads"
                )
            data = struct.pack(
                ">BBBQBH", self.version, int(self.type), self.ttl,
                self.timestamp & 0xFFFFFFFFFFFFFFFF, flags, payload_len,
            )
        data += sender
        if self.recipient_id is not None:
            data += self.recipient_id[:RECIPIENT_ID_SIZE].ljust(RECIPIENT_ID_SIZE, b"\x00")
        # Source route (v2 only): Count (1 byte) + Hops (N * 8 bytes)
        # Only valid when recipient_id is present
        if self.route and self.version >= 2 and self.recipient_id is not None:
            hops = [h[:SENDER_ID_SIZE].ljust(SENDER_ID_SIZE, b"\x00") for h in self.route]
            data += len(hops).to_bytes(1, "big")
            for h in hops:
                data += h
        data += wire_payload
        if self.signature is not None:
            data += self.signature[:SIGNATURE_SIZE]

        if padding:
            data = MessagePadding.pad(data, MessagePadding.optimal_block_size(len(data)))
        return data

    def data_for_signing(self) -> bytes:
        """
        Canonical bytes that the Ed25519 signature covers: the packet encoded
        WITHOUT a signature and with ttl=0 (TTL changes during relay), padded.
        Matches BitchatPacket.toBinaryDataForSigning() upstream.
        """
        unsigned = BitchatPacket(
            type=self.type, sender_id=self.sender_id, recipient_id=self.recipient_id,
            timestamp=self.timestamp, payload=self.payload, signature=None,
            ttl=0, version=self.version, route=self.route,
        )
        return unsigned.encode(padding=True)

    @staticmethod
    def decode(data: bytes) -> Optional["BitchatPacket"]:
        pkt = _decode_core(data)
        if pkt is not None:
            return pkt
        unpadded = MessagePadding.unpad(data)
        if unpadded is data or unpadded == data:
            return None
        return _decode_core(unpadded)

    # Backwards-compatible aliases used elsewhere in the codebase.
    def pack(self) -> bytes:
        return self.encode()

    @staticmethod
    def unpack(data: bytes) -> Optional["BitchatPacket"]:
        return BitchatPacket.decode(data)


def _decode_core(raw: bytes) -> Optional["BitchatPacket"]:
    try:
        if len(raw) < V1_HEADER_SIZE + SENDER_ID_SIZE:
            return None
        version = raw[0]
        if version not in (1, 2):
            return None

        length_field = 4 if version == 2 else 2
        header_size = V2_HEADER_SIZE if version == 2 else V1_HEADER_SIZE
        if len(raw) < header_size + SENDER_ID_SIZE:
            return None

        msg_type = raw[1]
        ttl = raw[2]
        timestamp = int.from_bytes(raw[3:11], "big")
        flags = raw[11]
        has_recipient = bool(flags & PacketFlags.HAS_RECIPIENT)
        has_signature = bool(flags & PacketFlags.HAS_SIGNATURE)
        is_compressed = bool(flags & PacketFlags.IS_COMPRESSED)
        has_route = version >= 2 and bool(flags & PacketFlags.HAS_ROUTE)

        if version == 2:
            payload_length = int.from_bytes(raw[12:16], "big")
            offset = 16
        else:
            payload_length = int.from_bytes(raw[12:14], "big")
            offset = 14

        sender_id = raw[offset:offset + SENDER_ID_SIZE]
        offset += SENDER_ID_SIZE

        recipient_id = None
        if has_recipient:
            if len(raw) < offset + RECIPIENT_ID_SIZE:
                return None
            recipient_id = raw[offset:offset + RECIPIENT_ID_SIZE]
            offset += RECIPIENT_ID_SIZE

        route = None
        if has_route and has_recipient:  # v2 source-routing hops (requires recipient)
            if len(raw) < offset + 1:
                return None
            route_count = raw[offset]
            offset += 1
            if len(raw) < offset + route_count * SENDER_ID_SIZE:
                return None
            route = []
            for i in range(route_count):
                hop = raw[offset:offset + SENDER_ID_SIZE]
                route.append(bytes(hop))
                offset += SENDER_ID_SIZE

        if is_compressed:
            if payload_length < length_field or len(raw) < offset + payload_length:
                return None
            original_size = int.from_bytes(raw[offset:offset + length_field], "big")
            offset += length_field
            compressed_size = payload_length - length_field
            compressed = raw[offset:offset + compressed_size]
            offset += compressed_size
            payload = _decompress(compressed, original_size)
            if payload is None:
                return None
        else:
            if len(raw) < offset + payload_length:
                return None
            payload = raw[offset:offset + payload_length]
            offset += payload_length

        signature = None
        if has_signature:
            if len(raw) < offset + SIGNATURE_SIZE:
                return None
            signature = raw[offset:offset + SIGNATURE_SIZE]
            offset += SIGNATURE_SIZE

        return BitchatPacket(
            type=msg_type, sender_id=sender_id, recipient_id=recipient_id,
            timestamp=timestamp, payload=payload, signature=signature,
            ttl=ttl, version=version, route=route,
        )
    except (struct.error, ValueError, IndexError):
        return None


# --------------------------------------------------------------------------- #
# BitchatMessage (public chat)
# --------------------------------------------------------------------------- #
# On the wire, a PUBLIC message packet's payload is simply the raw UTF-8 content
# string (see BLEService.sendMessage / BLEPublicMessageHandler upstream). The
# sender's nickname is resolved from its peer ID via the ANNOUNCE it sent
# earlier, so it is NOT carried in the message payload. This class is just a
# lightweight value object for local chat history / display.
@dataclass
class BitchatMessage:
    content: str = ""
    sender: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))


# --------------------------------------------------------------------------- #
# AnnouncementPacket (TLV: nickname + public keys)
# --------------------------------------------------------------------------- #
class _AnnTLV:
    NICKNAME = 0x01
    NOISE_PUBKEY = 0x02
    SIGNING_PUBKEY = 0x03
    DIRECT_NEIGHBORS = 0x04
    CAPABILITIES = 0x05


@dataclass
class AnnouncementPacket:
    nickname: str
    noise_public_key: bytes      # X25519 static key, 32 bytes
    signing_public_key: bytes    # Ed25519 signing key, 32 bytes
    direct_neighbors: list = field(default_factory=list)  # list of 8-byte peer IDs (TLV 0x04)
    capabilities: int = 0  # TLV 0x05: feature bitfield (little-endian)

    def encode(self) -> Optional[bytes]:
        nick_b = self.nickname.encode("utf-8")
        if len(nick_b) > 255 or len(self.noise_public_key) > 255 or len(self.signing_public_key) > 255:
            return None
        data = bytearray()
        for tlv_type, value in (
            (_AnnTLV.NICKNAME, nick_b),
            (_AnnTLV.NOISE_PUBKEY, self.noise_public_key),
            (_AnnTLV.SIGNING_PUBKEY, self.signing_public_key),
        ):
            data.append(tlv_type)
            data.append(len(value))
            data.extend(value)
        # TLV 0x04: DIRECT_NEIGHBORS (concatenation of 8-byte peer IDs)
        if self.direct_neighbors:
            neighbor_bytes = bytearray()
            seen = set()
            count = 0
            for nid in self.direct_neighbors:
                if count >= 10:
                    break
                nid_b = bytes(nid)[:8].ljust(8, b"\x00")
                key = nid_b
                if key in seen:
                    continue
                seen.add(key)
                neighbor_bytes.extend(nid_b)
                count += 1
            if len(neighbor_bytes) > 0:
                data.append(_AnnTLV.DIRECT_NEIGHBORS)
                data.append(len(neighbor_bytes))
                data.extend(neighbor_bytes)
        return bytes(data)

    @staticmethod
    def decode(data: bytes) -> Optional["AnnouncementPacket"]:
        nickname = noise = signing = None
        direct_neighbors = []
        capabilities = 0
        o = 0
        while o + 2 <= len(data):
            tlv_type = data[o]; length = data[o + 1]; o += 2
            if o + length > len(data):
                return None
            value = data[o:o + length]; o += length
            if tlv_type == _AnnTLV.NICKNAME:
                nickname = value.decode("utf-8", "replace")
            elif tlv_type == _AnnTLV.NOISE_PUBKEY:
                noise = bytes(value)
            elif tlv_type == _AnnTLV.SIGNING_PUBKEY:
                signing = bytes(value)
            elif tlv_type == _AnnTLV.DIRECT_NEIGHBORS:
                # Parse neighbor list: length/8 peer IDs, 8 bytes each (max 10)
                neighbors = []
                o2 = 0
                while o2 + 8 <= len(value) and len(neighbors) < 10:
                    nid = bytes(value[o2:o2 + 8])
                    neighbors.append(nid)
                    o2 += 8
                if not direct_neighbors and neighbors:  # first-wins
                    direct_neighbors = neighbors
            elif tlv_type == _AnnTLV.CAPABILITIES:
                # Parse as little-endian bitfield
                if len(value) > 0:
                    capabilities = int.from_bytes(value, "little")
            # unknown TLVs skipped for forward-compat
        if nickname is None or noise is None or signing is None:
            return None
        return AnnouncementPacket(nickname=nickname, noise_public_key=noise,
                                  signing_public_key=signing,
                                  direct_neighbors=direct_neighbors,
                                  capabilities=capabilities)


# --------------------------------------------------------------------------- #
# Fragmentation
# --------------------------------------------------------------------------- #
# Fragment payload layout: fragmentID(8) index(2) total(2) originalType(1) data
_FRAGMENT_HEADER_SIZE = 13


def parse_fragment(packet: "BitchatPacket") -> Optional[Tuple[bytes, int, int, int, bytes]]:
    p = packet.payload
    if len(p) < _FRAGMENT_HEADER_SIZE:
        return None
    fragment_id = p[0:8]
    index = int.from_bytes(p[8:10], "big")
    total = int.from_bytes(p[10:12], "big")
    original_type = p[12]
    fragment_data = p[13:]
    if total == 0 or index >= total:
        return None
    return fragment_id, index, total, original_type, fragment_data


class FragmentReassembler:
    """Buffers inbound fragments and yields the reassembled inner packet bytes."""

    def __init__(self, max_total: int = 10_000):
        self._buffers: Dict[Tuple[bytes, bytes], Dict[int, bytes]] = {}
        self._totals: Dict[Tuple[bytes, bytes], int] = {}
        self._max_total = max_total
        self.last_key = None

    def add(self, packet: "BitchatPacket") -> Optional[bytes]:
        parsed = parse_fragment(packet)
        if parsed is None:
            return None
        fragment_id, index, total, _original_type, data = parsed
        if total > self._max_total:
            return None
        key = (packet.sender_id, fragment_id)
        frags = self._buffers.setdefault(key, {})
        self._totals[key] = total
        frags[index] = data
        if len(frags) < total:
            return None
        # Complete: concatenate in index order, then drop the buffer.
        try:
            reassembled = b"".join(frags[i] for i in range(total))
        except KeyError:
            return None
        self._buffers.pop(key, None)
        self._totals.pop(key, None)
        self.last_key = key
        return reassembled
