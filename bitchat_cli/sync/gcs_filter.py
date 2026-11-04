"""Golomb-Coded Set (GCS) filter for gossip sync.

Implements the encoding/decoding used by bitchat-android GCSFilter (the
reference implementation) so the CLI interoperates with phone peers.

Hashing scheme (v1, fixed for cross-impl compatibility):

  - Packet ID: first 16 bytes of SHA-256 over [type | senderID | timestamp | payload]
  - GCS hash: h64 = first 8 bytes of SHA-256 over the 16-byte Packet ID,
    interpreted as an unsigned 64-bit integer, then masked to a positive
    63-bit value. Value = h64 % M, with 0 mapped to 1.
  - M = N * 2^P
  - Bitstream: MSB-first bit packing, Golomb-Rice with parameter P, where
    each delta x encodes q=(x-1)>>P ones, a zero, then (x-1)&((1<<P)-1).
"""
import hashlib
import math
from typing import Iterable, List, Set, Tuple


MAX_P = 32


def compute_p(fpr_percent: float) -> int:
    """P = ceil(log2(1/FPR)) for FPR as a percentage (e.g. 1.0 = 1%)."""
    fpr = fpr_percent / 100.0
    # Match Android GCSFilter.deriveP coercion (as a fraction).
    fpr = max(1e-6, min(0.25, fpr))
    return max(1, math.ceil(math.log2(1.0 / fpr)))


def estimate_max_elements_for_size(size_bytes: int, p: int) -> int:
    """Android GCSFilter.estimateMaxElementsForSize."""
    bits = max(size_bytes * 8, 8)
    per = max(p + 2, 3)
    return max(1, bits // per)


def h64(packet_id: bytes) -> int:
    """First 8 bytes of SHA-256(packet_id), masked to a positive 63-bit value."""
    h = hashlib.sha256(packet_id).digest()[:8]
    return int.from_bytes(h, "big") & 0x7FFFFFFFFFFFFFFF


def gcs_hash(packet_id: bytes) -> int:
    """Return h64 (masked) for a packet ID."""
    return h64(packet_id)


def _encode_gr(values: List[int], p: int) -> bytes:
    mask = (1 << p) - 1
    bits = []
    prev = 0
    for v in values:
        delta = v - prev
        prev = v
        x = delta
        q = (x - 1) >> p
        r = (x - 1) & mask
        bits.extend([1] * q)
        bits.append(0)
        for i in range(p - 1, -1, -1):
            bits.append((r >> i) & 1)
    # Pack MSB-first
    data = bytearray()
    byte_val = 0
    bit_count = 0
    for b in bits:
        byte_val = (byte_val << 1) | b
        bit_count += 1
        if bit_count == 8:
            data.append(byte_val)
            byte_val = 0
            bit_count = 0
    if bit_count > 0:
        byte_val <<= (8 - bit_count)
        data.append(byte_val)
    return bytes(data)


def build_filter(packet_ids: List[bytes], size_bytes: int = 256,
                 fpr_percent: float = 1.0) -> Tuple[int, int, bytes]:
    """Build a GCS filter mirroring Android GCSFilter.buildFilter."""
    p = compute_p(fpr_percent)
    n_cap = estimate_max_elements_for_size(size_bytes, p)
    trimmed_n = min(len(packet_ids), n_cap)
    if trimmed_n < 0:
        trimmed_n = 0

    def _mapped(n):
        m = (n << p) if n > 0 else (1 << p)
        if m < 1:
            m = 1
        out = []
        for pid in packet_ids[:n]:
            v = h64(pid) % m
            if v == 0:
                v = 1
            out.append(v)
        # distinct + sorted
        return m, sorted(set(out))

    # Initial
    m, mapped = _mapped(trimmed_n if trimmed_n > 0 else 0)
    if trimmed_n == 0:
        m = 1 << p
        mapped = []
    encoded = _encode_gr(mapped, p) if mapped else b""

    # Trim until fits
    while len(encoded) > size_bytes and trimmed_n > 0:
        trimmed_n = (trimmed_n * 9) // 10
        if trimmed_n < 1:
            trimmed_n = 0
        if trimmed_n == 0:
            m = 1 << p
            mapped = []
            encoded = b""
            break
        m, mapped = _mapped(trimmed_n)
        encoded = _encode_gr(mapped, p)

    if trimmed_n == 0:
        m = 1 << p
        encoded = b""

    return p, m, encoded


def decode_filter(P: int, M: int, data: bytes) -> Set[int]:
    """Decode a GCS bitstream into a set of mapped values (Android decodeToSortedSet)."""
    if P < 1 or P > MAX_P or M <= 1 or not data:
        return set()

    # Unpack bits MSB-first
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    values = set()
    idx = 0
    n_bits = len(bits)
    acc = 0
    mask = (1 << P) - 1

    def read_bit():
        nonlocal idx
        if idx >= n_bits:
            return None
        b = bits[idx]
        idx += 1
        return b

    while idx < n_bits:
        # unary quotient
        q = 0
        while True:
            b = read_bit()
            if b is None:
                # EOF
                return values
            if b == 1:
                q += 1
            else:
                break
        # read remainder P bits
        r = 0
        ok = True
        for _ in range(P):
            b = read_bit()
            if b is None:
                ok = False
                break
            r = (r << 1) | b
        if not ok:
            break
        x = (q << P) + r + 1
        acc += x
        if acc >= M:
            break
        values.add(acc)

    return values


def contains(P: int, M: int, filter_values: Set[int], packet_id: bytes) -> bool:
    """Check if a packet ID is in the decoded filter values."""
    if M <= 1:
        return False
    v = h64(packet_id) % M
    if v == 0:
        v = 1
    return v in filter_values
