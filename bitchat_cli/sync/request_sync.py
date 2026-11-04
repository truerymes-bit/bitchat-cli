"""RequestSyncPacket encoding/decoding.

MessageType: REQUEST_SYNC (0x21)

Payload: TLV with 16-bit big-endian length fields (type, length16, value)
  - 0x01: P (uint8) — Golomb-Rice parameter
  - 0x02: M (uint32) — hash range N * 2^P
  - 0x03: data (opaque) — GCS bitstream (MSB-first bit packing)

Wire format per TLV: [type:1][length:2 BE][value:length]
"""
import struct
from typing import Optional, Tuple


TLV_P = 0x01
TLV_M = 0x02
TLV_DATA = 0x03


def encode(P: int, M: int, data: bytes) -> bytes:
    """Encode P, M, data into the REQUEST_SYNC payload."""
    payload = bytearray()
    # TLV 0x01: P (uint8)
    payload.append(TLV_P)
    payload += struct.pack(">H", 1)
    payload.append(P & 0xFF)
    # TLV 0x02: M (uint32)
    payload.append(TLV_M)
    payload += struct.pack(">H", 4)
    payload += struct.pack(">I", M & 0xFFFFFFFF)
    # TLV 0x03: data
    payload.append(TLV_DATA)
    payload += struct.pack(">H", len(data))
    payload += data
    return bytes(payload)


def decode(payload: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Decode a REQUEST_SYNC payload into (P, M, data).

    Returns None if malformed.
    """
    if not payload:
        return None
    P = None
    M = None
    data = b""
    offset = 0
    n = len(payload)
    while offset + 3 <= n:
        if offset + 3 > n:
            return None
        tlv_type = payload[offset]
        length = struct.unpack(">H", payload[offset + 1:offset + 3])[0]
        offset += 3
        if offset + length > n:
            return None
        value = payload[offset:offset + length]
        offset += length
        if tlv_type == TLV_P:
            if length != 1:
                return None
            P = value[0]
        elif tlv_type == TLV_M:
            if length != 4:
                return None
            M = struct.unpack(">I", value)[0]
        elif tlv_type == TLV_DATA:
            data = value
        # Unknown TLVs ignored
    if P is None or M is None:
        return None
    # Validation
    if P < 1 or P > 32:
        return None
    if M <= 0:
        return None
    if len(data) > 1024:
        return None
    return P, M, data
