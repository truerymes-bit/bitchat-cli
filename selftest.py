# selftest.py
#
# Offline checks for the bitchat wire protocol implementation. These do NOT
# touch Bluetooth; they verify that encoding/decoding round-trips and that our
# signatures match the canonical form the real app verifies against.
#
#   python selftest.py

import os

from cryptography.hazmat.primitives.asymmetric import ed25519

from bitchat_cli.identity import IdentityKeys
from bitchat_cli.media import (
    BitchatFilePacket,
    MAX_PAYLOAD_BYTES,
    category_for_mime,
    message_prefix,
    mime_for_extension,
)
from bitchat_cli.protocol import (
    AnnouncementPacket,
    BitchatPacket,
    MessagePadding,
    MessageType,
    FragmentReassembler,
    SIGNATURE_SIZE,
)

# ble_service pulls in noise/bleak/dbus; skip the DM retry tests when those
# are unavailable (the rest of the suite is pure protocol and always runs).
try:
    import bitchat_cli.ble_service as _ble_service
    from bitchat_cli.chat_state import ChatState as _ChatState
    _HAVE_BLE_SERVICE = True
except ImportError:
    _HAVE_BLE_SERVICE = False

passed = 0


def check(name, condition):
    global passed
    if condition:
        passed += 1
        print(f"  ok  - {name}")
    else:
        raise AssertionError(f"FAILED - {name}")


def test_padding():
    check("optimal block size small -> 256", MessagePadding.optimal_block_size(50) == 256)
    check("optimal block size 300 -> 512", MessagePadding.optimal_block_size(300) == 512)
    data = b"hello world"
    padded = MessagePadding.pad(data, 256)
    check("padded length is block size", len(padded) == 256)
    check("unpad restores original", MessagePadding.unpad(padded) == data)


def test_packet_roundtrip():
    pkt = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=os.urandom(8),
        recipient_id=None,
        payload=b"gm from the CLI",
        ttl=7,
    )
    decoded = BitchatPacket.decode(pkt.encode())
    check("packet decodes", decoded is not None)
    check("type preserved", decoded.type == MessageType.MESSAGE)
    check("sender preserved", decoded.sender_id == pkt.sender_id)
    check("payload preserved (padding ignored)", decoded.payload == pkt.payload)
    check("ttl preserved", decoded.ttl == 7)

    # With recipient + signature flags.
    pkt2 = BitchatPacket(
        type=MessageType.ANNOUNCE, sender_id=os.urandom(8),
        recipient_id=b"\xff" * 8, payload=b"x" * 100, signature=os.urandom(SIGNATURE_SIZE),
    )
    d2 = BitchatPacket.decode(pkt2.encode())
    check("recipient preserved", d2.recipient_id == b"\xff" * 8)
    check("signature preserved", d2.signature == pkt2.signature)
    check("payload preserved w/ sig", d2.payload == pkt2.payload)


def test_signature_matches_canonical():
    keys = IdentityKeys()
    pkt = BitchatPacket(
        type=MessageType.MESSAGE, sender_id=os.urandom(8),
        recipient_id=None, payload=b"signed message", ttl=7,
    )
    pkt.signature = keys.sign(pkt.data_for_signing())
    wire = pkt.encode()

    # The receiver decodes, reconstructs the canonical bytes from decoded fields
    # (ttl forced to 0, no signature) and verifies. Simulate that here.
    decoded = BitchatPacket.decode(wire)
    canonical = decoded.data_for_signing()
    pub = ed25519.Ed25519PublicKey.from_public_bytes(keys.signing_public_key_bytes())
    try:
        pub.verify(decoded.signature, canonical)
        ok = True
    except Exception:
        ok = False
    check("ed25519 signature verifies against canonical bytes", ok)
    check("canonical bytes are ttl-independent",
          BitchatPacket.decode(wire).data_for_signing() == pkt.data_for_signing())


def test_announce():
    keys = IdentityKeys()
    ann = AnnouncementPacket(
        nickname="user-abcd",
        noise_public_key=keys.noise_public_key_bytes(),
        signing_public_key=keys.signing_public_key_bytes(),
    )
    decoded = AnnouncementPacket.decode(ann.encode())
    check("announce decodes", decoded is not None)
    check("nickname preserved", decoded.nickname == "user-abcd")
    check("noise key preserved (32B)", decoded.noise_public_key == keys.noise_public_key_bytes())
    check("signing key preserved (32B)", decoded.signing_public_key == keys.signing_public_key_bytes())


def test_fragment_reassembly():
    sender = os.urandom(8)
    # A large inner packet that would exceed one BLE write.
    inner = BitchatPacket(
        type=MessageType.MESSAGE, sender_id=sender, recipient_id=None,
        payload=b"A" * 1500, ttl=7,
    )
    inner_bytes = inner.encode()

    fragment_id = os.urandom(8)
    chunk = 400
    chunks = [inner_bytes[i:i + chunk] for i in range(0, len(inner_bytes), chunk)]
    total = len(chunks)

    reasm = FragmentReassembler()
    result = None
    for index, c in enumerate(chunks):
        payload = (fragment_id + index.to_bytes(2, "big") + total.to_bytes(2, "big")
                   + bytes([int(MessageType.MESSAGE)]) + c)
        frag = BitchatPacket(type=MessageType.FRAGMENT, sender_id=sender, payload=payload)
        result = reasm.add(frag)
    check("fragments reassemble", result == inner_bytes)
    rebuilt = BitchatPacket.decode(result)
    check("reassembled packet decodes", rebuilt is not None and rebuilt.payload == b"A" * 1500)


def test_file_packet_roundtrip():
    # A PNG-ish blob with name + mime.
    content = b"\x89PNG\r\n\x1a\n" + b"Z" * 500
    fp = BitchatFilePacket(
        content=content, file_name="photo.png", file_size=len(content),
        mime_type="image/png",
    )
    encoded = fp.encode()
    check("file packet encodes", encoded is not None)
    d = BitchatFilePacket.decode(encoded)
    check("file packet decodes", d is not None)
    check("content preserved", d.content == content)
    check("file_name preserved", d.file_name == "photo.png")
    check("mime preserved", d.mime_type == "image/png")
    check("file_size preserved", d.file_size == len(content))

    # Minimal packet: content only (no name / mime).
    bare = BitchatFilePacket(content=b"\x00\x01\x02\x03")
    db = BitchatFilePacket.decode(bare.encode())
    check("bare file packet decodes", db is not None and db.content == b"\x00\x01\x02\x03")
    check("bare file_size defaults to content length", db.file_size == 4)


def test_file_packet_oversize_rejected():
    huge = BitchatFilePacket(content=b"\x00" * (MAX_PAYLOAD_BYTES + 1))
    check("oversize file packet rejected by encode", huge.encode() is None)


def test_file_transfer_packet_wrap():
    # A FILE_TRANSFER BitchatPacket carrying a file TLV must round-trip the bytes.
    content = b"\xff\xd8\xff" + b"J" * 2000  # jpeg-ish, big enough to need fragmenting
    fp = BitchatFilePacket(content=content, file_name="clip.jpg", mime_type="image/jpeg")
    payload = fp.encode()
    pkt = BitchatPacket(
        type=MessageType.FILE_TRANSFER, sender_id=os.urandom(8),
        recipient_id=None, payload=payload, ttl=7,
    )
    decoded = BitchatPacket.decode(pkt.encode())
    check("file-transfer packet decodes", decoded is not None)
    check("file-transfer type preserved", decoded.type == MessageType.FILE_TRANSFER)
    inner = BitchatFilePacket.decode(decoded.payload)
    check("inner file content recovered", inner is not None and inner.content == content)


def test_large_file_packet_needs_v2():
    # Regression: a payload over 64 KiB must encode as a version-2 packet
    # (4-byte length). Version 1 (2-byte length) must refuse it loudly rather
    # than silently overflowing struct's 'H' field.
    content = b"\x89PNG\r\n\x1a\n" + os.urandom(200_000)  # ~200 KiB, like a real image
    fp = BitchatFilePacket(content=content, file_name="map.png", mime_type="image/png")
    payload = fp.encode()
    check("large file payload exceeds the v1 length limit", len(payload) > 0xFFFF)

    # Version 1 must raise (this is exactly the crash we fixed).
    v1 = BitchatPacket(type=MessageType.FILE_TRANSFER, sender_id=os.urandom(8),
                       recipient_id=None, payload=payload, ttl=7, version=1)
    try:
        v1.encode()
        raised = False
    except ValueError:
        raised = True
    check("version-1 encode rejects oversize payload", raised)

    # Version 2 must encode, sign-canonicalise, decode, and recover the content.
    keys = IdentityKeys()
    v2 = BitchatPacket(type=MessageType.FILE_TRANSFER, sender_id=os.urandom(8),
                       recipient_id=None, payload=payload, ttl=7, version=2)
    v2.signature = keys.sign(v2.data_for_signing())
    decoded = BitchatPacket.decode(v2.encode())
    check("version-2 large packet decodes", decoded is not None)
    check("version-2 preserved", decoded.version == 2)
    check("version-2 payload length preserved", len(decoded.payload) == len(payload))
    inner = BitchatFilePacket.decode(decoded.payload)
    check("v2 inner image content recovered", inner is not None and inner.content == content)

    # The signature still verifies against the reconstructed canonical bytes.
    pub = ed25519.Ed25519PublicKey.from_public_bytes(keys.signing_public_key_bytes())
    try:
        pub.verify(decoded.signature, decoded.data_for_signing())
        ok = True
    except Exception:
        ok = False
    check("v2 file-transfer signature verifies", ok)


def test_file_fragment_reassembly():
    # A file packet exceeding one BLE write reassembles back to identical bytes.
    sender = os.urandom(8)
    fp = BitchatFilePacket(content=b"M" * 4000, file_name="big.bin",
                           mime_type="application/octet-stream")
    inner = BitchatPacket(
        type=MessageType.FILE_TRANSFER, sender_id=sender, recipient_id=None,
        payload=fp.encode(), ttl=7,
    )
    inner_bytes = inner.encode()

    fragment_id = os.urandom(8)
    chunk = 440
    chunks = [inner_bytes[i:i + chunk] for i in range(0, len(inner_bytes), chunk)]
    total = len(chunks)
    reasm = FragmentReassembler()
    result = None
    for index, c in enumerate(chunks):
        payload = (fragment_id + index.to_bytes(2, "big") + total.to_bytes(2, "big")
                   + bytes([int(MessageType.FILE_TRANSFER)]) + c)
        frag = BitchatPacket(type=MessageType.FRAGMENT, sender_id=sender, payload=payload)
        result = reasm.add(frag)
    check("file fragments reassemble", result == inner_bytes)
    rebuilt = BitchatPacket.decode(result)
    check("reassembled file packet decodes",
          rebuilt is not None and BitchatFilePacket.decode(rebuilt.payload).content == b"M" * 4000)


def test_mime_helpers():
    check("jpg -> image/jpeg", mime_for_extension(".jpg") == "image/jpeg")
    check("m4a -> audio category", category_for_mime("audio/m4a") == "audio")
    check("mp4 video -> octet-stream", mime_for_extension("mp4") == "application/octet-stream")
    check("octet-stream -> file category", category_for_mime("application/octet-stream") == "file")
    check("image prefix", message_prefix("image") == "[image] ")
    check("audio prefix is [voice]", message_prefix("audio") == "[voice] ")


def test_public_message_payload_is_raw():
    # Public message payload must be the raw UTF-8 content (not a TLV blob).
    content = "hello, mesh 👋"
    pkt = BitchatPacket(type=MessageType.MESSAGE, sender_id=os.urandom(8),
                        payload=content.encode("utf-8"))
    decoded = BitchatPacket.decode(pkt.encode())
    check("public payload is raw utf-8 content",
          decoded.payload.decode("utf-8") == content)


def test_compute_route_shape():
    # compute_route returns intermediate hops only: [] for direct, [..] for
    # multi-hop, None when unreachable or self-to-self.
    from bitchat_cli.chat_state import ChatState
    SELF = "aaaaaaaaaaaaaaaa"
    A = "bbbbbbbbbbbbbbbb"
    B = "cccccccccccccccc"
    state = ChatState(nickname="self", my_peer_id=bytes.fromhex(SELF))
    state.add_direct_peer(A)
    state.update_topology(A, [bytes.fromhex(B)], timestamp=1)
    state.update_topology(B, [bytes.fromhex(A)], timestamp=1)
    check("direct neighbor -> []",
          state.compute_route(SELF, A) == [])
    check("two-hop chain -> [A]",
          state.compute_route(SELF, B) == [A])
    check("unreachable -> None",
          state.compute_route(SELF, "dddddddddddddddd") is None)
    check("self-to-self -> None",
          state.compute_route(SELF, SELF) is None)


def test_dm_ack_retry_same_msg_id():
    """A retried DM reuses its msg_id: no new ack entry, no extra echo."""
    import asyncio as _asyncio
    import types as _types

    ble = _ble_service
    state = _ChatState(nickname="self", my_peer_id=bytes.fromhex("aa" * 16))
    peer = "bb" * 16
    state.set_peer_info(peer, "bob", b"k" * 32, b"s" * 32)

    svc = ble.BLEService(state, lambda: None)
    svc._running = True

    broadcasts = []
    echoes = []
    warnings = []

    class FakeSession:
        def __init__(self):
            self.created_at = ble.time.monotonic()
            self.is_finished = True

        def encrypt(self, plaintext):
            return plaintext

    svc._noise_sessions[peer] = FakeSession()

    async def fake_broadcast(packet):
        if packet.type != MessageType.NOISE_ENCRYPTED:
            return
        tlv = packet.payload[1:]  # fake session: ciphertext == plaintext
        assert tlv[0] == 0
        ln = tlv[1]
        broadcasts.append(tlv[2:2 + ln].decode())

    svc._broadcast = fake_broadcast
    svc._chat = lambda *a, **k: echoes.append((a, k))
    svc._warn = lambda msg, conv=None: warnings.append(msg)

    clock = [1000.0]
    real_time = ble.time
    ble.time = _types.SimpleNamespace(monotonic=lambda: clock[0], time=real_time.time)
    real_sleep = _asyncio.sleep
    real_ack_timeout = ble.DM_ACK_TIMEOUT
    real_max_retries = ble.DM_ACK_MAX_RETRIES
    ble.DM_ACK_TIMEOUT = 0.0005

    async def fake_sleep(delay, result=None):
        # Only the retry loop's 5s pass advances the clock; the test's own
        # yields must not, or the fake session would age out.
        await real_sleep(0)  # yield to the event loop
        if delay >= 1.0:
            clock[0] += 0.001
        return result

    _asyncio.sleep = fake_sleep
    try:
        async def scenario():
            await svc.send_private_message(peer, "hello")
            task = _asyncio.ensure_future(svc._dm_ack_retry_loop())
            for _ in range(200000):
                if not svc._pending_acks and len(broadcasts) >= 1 + real_max_retries:
                    break
                await _asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except _asyncio.CancelledError:
                pass

        _asyncio.run(scenario())
    finally:
        _asyncio.sleep = real_sleep
        ble.time = real_time
        ble.DM_ACK_TIMEOUT = real_ack_timeout

    check("initial + max retries broadcasts",
          len(broadcasts) == 1 + real_max_retries)
    check("all broadcasts carry the same msg_id", len(set(broadcasts)) == 1)
    check("exactly one echo", len(echoes) == 1)
    check("pending acks drained", svc._pending_acks == {})
    check("exactly one failure warning", len(warnings) == 1)
    check("failure warning names the peer",
          bool(warnings) and "bob" in warnings[0] and "not confirmed delivered" in warnings[0])


def test_dm_ack_received_stops_retries():
    """An ack after the first retry stops further retries."""
    import asyncio as _asyncio
    import types as _types

    ble = _ble_service
    state = _ChatState(nickname="self", my_peer_id=bytes.fromhex("aa" * 16))
    peer = "bb" * 16
    state.set_peer_info(peer, "bob", b"k" * 32, b"s" * 32)

    svc = ble.BLEService(state, lambda: None)
    svc._running = True

    broadcasts = []
    echoes = []
    warnings = []

    class FakeSession:
        def __init__(self):
            self.created_at = ble.time.monotonic()
            self.is_finished = True

        def encrypt(self, plaintext):
            return plaintext

    svc._noise_sessions[peer] = FakeSession()

    async def fake_broadcast(packet):
        if packet.type != MessageType.NOISE_ENCRYPTED:
            return
        tlv = packet.payload[1:]
        ln = tlv[1]
        msg_id = tlv[2:2 + ln].decode()
        broadcasts.append(msg_id)
        if len(broadcasts) == 2:
            # The ack arrives right after the first retry.
            svc._pending_acks.pop(msg_id, None)

    svc._broadcast = fake_broadcast
    svc._chat = lambda *a, **k: echoes.append((a, k))
    svc._warn = lambda msg, conv=None: warnings.append(msg)

    clock = [1000.0]
    real_time = ble.time
    ble.time = _types.SimpleNamespace(monotonic=lambda: clock[0], time=real_time.time)
    real_sleep = _asyncio.sleep
    real_ack_timeout = ble.DM_ACK_TIMEOUT
    ble.DM_ACK_TIMEOUT = 0.0005

    async def fake_sleep(delay, result=None):
        # Only the retry loop's 5s pass advances the clock; the test's own
        # yields must not, or the fake session would age out.
        await real_sleep(0)  # yield to the event loop
        if delay >= 1.0:
            clock[0] += 0.001
        return result

    _asyncio.sleep = fake_sleep
    try:
        async def scenario():
            await svc.send_private_message(peer, "hello")
            task = _asyncio.ensure_future(svc._dm_ack_retry_loop())
            for _ in range(200000):
                if len(broadcasts) >= 2:
                    break
                await _asyncio.sleep(0)
            for _ in range(50):
                await _asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except _asyncio.CancelledError:
                pass

        _asyncio.run(scenario())
    finally:
        _asyncio.sleep = real_sleep
        ble.time = real_time
        ble.DM_ACK_TIMEOUT = real_ack_timeout

    check("initial + one retry broadcast", len(broadcasts) == 2)
    check("ack removed the pending entry", svc._pending_acks == {})
    check("no failure warning", warnings == [])
    check("exactly one echo", len(echoes) == 1)


if __name__ == "__main__":
    print("Running bitchat-cli protocol self-tests...\n")
    tests = [
        test_padding,
        test_packet_roundtrip,
        test_signature_matches_canonical,
        test_announce,
        test_fragment_reassembly,
        test_file_packet_roundtrip,
        test_file_packet_oversize_rejected,
        test_file_transfer_packet_wrap,
        test_large_file_packet_needs_v2,
        test_file_fragment_reassembly,
        test_mime_helpers,
        test_public_message_payload_is_raw,
        test_compute_route_shape,
    ]
    if _HAVE_BLE_SERVICE:
        tests.append(test_dm_ack_retry_same_msg_id)
        tests.append(test_dm_ack_received_stops_retries)
    for test in tests:
        print(f"{test.__name__}:")
        test()
    print(f"\nAll {passed} checks passed. ✅")
