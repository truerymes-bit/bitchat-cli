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


# ---------------------------------------------------------------------------
# DM outbox tests. These use a real in-process Noise_XX handshake between the
# service and a "phone" built from the project's own NoiseSession, so every
# 0x02/0x03 payload is produced and decrypted by real code. No mocks, no
# patched time/asyncio. Clock is a FakeClock passed to the constructor.
# ---------------------------------------------------------------------------
import asyncio as _aio
import hashlib as _hashlib
import itertools as _itertools

from bitchat_cli import ble_service as _ble
from bitchat_cli.chat_state import ChatState as _ChatState
from bitchat_cli.identity import IdentityKeys as _IdentityKeys
from bitchat_cli.protocol import BitchatPacket as _Packet, MessageType as _MT


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = float(t)

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += float(seconds)


class RecordingBLEService(_ble.BLEService):
    """BLEService whose outbound packets are recorded instead of written to BLE."""

    def __init__(self, state, clock):
        super().__init__(state, lambda: None, clock=clock)
        self.sent = []    # (clock time, packet)
        self.lines = []   # (conv, line)
        self.dm_status_events = []  # (conv, msg_id, state) from the service hook
        self.dm_status_cb = lambda conv, msg_id, state: self.dm_status_events.append((conv, msg_id, state))

    async def _broadcast(self, packet):
        self.sent.append((self.clock(), packet))

    def _emit(self, line, conv=None, msg_id=None, is_self=False):
        self.lines.append((conv, line))

    def dm_packets(self):
        return [p for _, p in self.sent if p.type == _MT.NOISE_ENCRYPTED]

    def handshake_packets(self):
        return [(t, p) for t, p in self.sent if p.type == _MT.NOISE_HANDSHAKE]


class Phone:
    def __init__(self):
        self.keys = _IdentityKeys()
        self.peer_id = _hashlib.sha256(self.keys.noise_public_key_bytes()).digest()[:8]
        self.peer_hex = self.peer_id.hex()
        self.session = None


def _make(clock):
    state = _ChatState(nickname="self", my_peer_id=bytes.fromhex("aa" * 8))
    svc = RecordingBLEService(state, clock)
    svc._running = True
    phone = Phone()
    state.set_peer_info(phone.peer_hex, "bob",
                        phone.keys.noise_public_key_bytes(),
                        phone.keys.signing_public_key_bytes())
    return svc, phone


async def _establish(svc, phone):
    """Real Noise_XX handshake: service is initiator, phone is responder."""
    svc._initiate_noise_handshake(phone.peer_hex, phone.keys.noise_public_key_bytes())
    await _aio.sleep(0)
    await _complete_handshake(svc, phone)


async def _complete_handshake(svc, phone):
    """Answer the service's latest handshake message with the phone's side."""
    await _aio.sleep(0)
    msg1 = svc.handshake_packets()[-1][1].payload
    phone.session = _ble.NoiseSession(
        phone.keys.noise_private_key_bytes(),
        svc.state.identity.noise_public_key_bytes(),
        is_initiator=False)
    msg2 = phone.session.handle_handshake_message(msg1)
    assert msg2, "phone produced no msg2"
    svc._dispatch(_Packet(type=_MT.NOISE_HANDSHAKE, sender_id=phone.peer_id,
                          recipient_id=svc.state.my_peer_id, payload=msg2))
    await _aio.sleep(0)
    msg3 = svc.handshake_packets()[-1][1].payload
    phone.session.handle_handshake_message(msg3)
    assert phone.session.is_finished, "phone handshake not finished"
    assert svc._noise_sessions[phone.peer_hex].is_finished, "service handshake not finished"


def _phone_to_service(svc, phone, plaintext):
    """Phone encrypts a NoisePayload and the service receives it via _dispatch."""
    svc._dispatch(_Packet(type=_MT.NOISE_ENCRYPTED, sender_id=phone.peer_id,
                          recipient_id=svc.state.my_peer_id,
                          payload=phone.session.encrypt(plaintext)))


def _ack(kind, msg_id):
    return bytes([kind]) + msg_id.encode("utf-8")


def _decrypt_dm(phone, packet):
    pt = phone.session.decrypt(packet.payload)
    assert pt[0] == 0x01, f"not a PRIVATE_MESSAGE: type {pt[0]}"
    rest = pt[1:]
    assert rest[0] == 0x00
    mid = rest[2:2 + rest[1]].decode()
    rest = rest[2 + rest[1]:]
    assert rest[0] == 0x01
    return mid, rest[2:2 + rest[1]].decode()


def test_dm_sent_once_never_retransmitted():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        msg_id = await svc.send_private_message(phone.peer_hex, "hello phone")
        await _aio.sleep(0)
        check("DM with ready session transmits immediately", len(svc.dm_packets()) == 1)
        check("sent DM decrypts on phone side to same msg_id and text",
              _decrypt_dm(phone, svc.dm_packets()[0]) == (msg_id, "hello phone"))
        check("state after broadcast is sent", svc._outbox[msg_id]["state"] == "sent")
        for _ in range(60):
            clock.advance(60)  # one hour of ticks, no ack ever arrives
            await svc._outbox_tick()
            await _aio.sleep(0)
        check("never retransmitted after many ticks (still exactly 1 DM)",
              len(svc.dm_packets()) == 1)
        check("state ends unconfirmed", svc._outbox[msg_id]["state"] == "unconfirmed")

    _aio.run(run())


def test_dm_delivery_states_never_downgrade():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        msg_id = await svc.send_private_message(phone.peer_hex, "status")
        st = lambda: svc._outbox[msg_id]["state"]
        check("sent before any receipt", st() == "sent")
        _phone_to_service(svc, phone, _ack(0x03, msg_id))
        check("real 0x03 moves sent -> delivered", st() == "delivered")
        clock.advance(600)
        _phone_to_service(svc, phone, _ack(0x02, msg_id))
        check("real 0x02 moves delivered -> read", st() == "read")
        _phone_to_service(svc, phone, _ack(0x03, msg_id))
        check("late 0x03 after read does not downgrade", st() == "read")
        await svc._outbox_tick()
        check("tick does not mark a read DM unconfirmed", st() == "read")
        check("no DM retransmitted by any of this", len(svc.dm_packets()) == 1)

    _aio.run(run())


def test_queued_dm_waits_for_handshake_and_backoff():
    clock = FakeClock(1000.0)
    t0 = clock()

    async def run():
        svc, phone = _make(clock)
        msg_id = await svc.send_private_message(phone.peer_hex, "later")
        await _aio.sleep(0)
        check("no session: DM stays queued", svc._outbox[msg_id]["state"] == "sending")
        check("no session: nothing transmitted at send time",
              svc.dm_packets() == [] and svc.handshake_packets() == [])
        # Tick every second for 60 s and record when handshakes are kicked.
        kicks = []
        for _ in range(61):
            before = len(svc.handshake_packets())
            await svc._outbox_tick()
            await _aio.sleep(0)
            if len(svc.handshake_packets()) > before:
                kicks.append(clock() - t0)
            clock.advance(1)
        # Schedule implied by Android HANDSHAKE_RETRY_BACKOFF_MS: kick, then wait
        # backoff[attempt] (last value repeats).
        expected = []
        at = 0.0
        for i in range(len(kicks)):
            expected.append(at)
            at += _ble.HANDSHAKE_RETRY_BACKOFF_MS[min(i, len(_ble.HANDSHAKE_RETRY_BACKOFF_MS) - 1)] / 1000.0
        check(f"handshake kicks follow Android backoff {kicks}", kicks == expected and len(kicks) >= 4)
        check("still queued while no session", svc._outbox[msg_id]["state"] == "sending")
        check("no DM sent before handshake finishes", svc.dm_packets() == [])
        await _complete_handshake(svc, phone)
        await svc._outbox_tick()
        await _aio.sleep(0)
        check("flushed after handshake finished: 1 DM", len(svc.dm_packets()) == 1)
        check("flushed DM decrypts to queued text",
              _decrypt_dm(phone, svc.dm_packets()[0])[1] == "later")
        check("state sent after flush", svc._outbox[msg_id]["state"] == "sent")

    _aio.run(run())


def test_queue_expiry_marks_failed_and_sends_nothing():
    clock = FakeClock()
    t0 = clock()

    async def run():
        svc, phone = _make(clock)
        msg_id = await svc.send_private_message(phone.peer_hex, "stuck")
        check("content over 255 bytes is refused",
              await svc.send_private_message(phone.peer_hex, "x" * 256) is None)
        ttl = _ble.OUTBOX_MESSAGE_TTL_MS / 1000.0
        while clock() - t0 <= ttl + 3600:
            clock.advance(3600)
            await svc._outbox_tick()
            await _aio.sleep(0)
        check("expired queued DM is failed", svc._outbox[msg_id]["state"] == "failed")
        check("expired DM sends no DM packet", svc.dm_packets() == [])
        check("expiry is reported", any("expired" in line for _, line in svc.lines))

    _aio.run(run())


def test_incoming_dm_gets_real_delivery_ack():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        incoming = "PHONE-MSG-0001"
        tlv = bytes([0x00, len(incoming)]) + incoming.encode() + bytes([0x01, 2]) + b"hi"
        _phone_to_service(svc, phone, bytes([0x01]) + tlv)
        await _aio.sleep(0)
        await _aio.sleep(0)
        acks = svc.dm_packets()
        check("incoming DM produces exactly one ack packet", len(acks) == 1)
        pt = phone.session.decrypt(acks[0].payload)
        check("ack is a real 0x03 that decrypts on the phone to the same msg_id",
              pt[0] == 0x03 and pt[1:].decode() == incoming)

    _aio.run(run())


class _PhoneReader:
    """Decrypts the service's NOISE_ENCRYPTED payloads once each, in order (replay window)."""

    def __init__(self, svc, phone):
        self.svc = svc
        self.phone = phone
        self.n = 0

    def new_plaintexts(self):
        packets = self.svc.dm_packets()
        out = [self.phone.session.decrypt(p.payload) for p in packets[self.n:]]
        self.n = len(packets)
        return out


def _receipt_ids(plaintexts):
    return [pt[1:].decode() for pt in plaintexts if pt[0] == 0x02]


def test_read_receipts_once_per_unread_message():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        peer = phone.peer_hex
        reader = _PhoneReader(svc, phone)

        def phone_dm(mid):
            tlv = bytes([0x00, len(mid)]) + mid.encode() + bytes([0x01, 2]) + b"hi"
            _phone_to_service(svc, phone, bytes([0x01]) + tlv)

        phone_dm("IN-A")
        phone_dm("IN-B")
        await _aio.sleep(0)
        await _aio.sleep(0)
        check("no read receipt while the tab is not active",
              _receipt_ids(reader.new_plaintexts()) == [])
        await svc.read_receipts_for_peer(peer)
        check("tab activation sends exactly one 0x02 per unread msg_id",
              sorted(_receipt_ids(reader.new_plaintexts())) == ["IN-A", "IN-B"])
        await svc.read_receipts_for_peer(peer)
        check("second activation sends none",
              _receipt_ids(reader.new_plaintexts()) == [])

        # No finished session: not marked sent, stays unread, next trigger retries.
        phone_dm("IN-C")
        await _aio.sleep(0)
        await _aio.sleep(0)
        saved = svc._noise_sessions.pop(peer)
        await svc.read_receipts_for_peer(peer)
        check("no session: nothing sent and message stays unread",
              _receipt_ids(reader.new_plaintexts()) == [] and svc._unread_incoming.get(peer) == ["IN-C"])
        svc._noise_sessions[peer] = saved
        await svc.read_receipts_for_peer(peer)
        check("next trigger with a session sends the held receipt",
              _receipt_ids(reader.new_plaintexts()) == ["IN-C"])

        # Incoming DM while its tab is visible and focused: receipt goes out at once.
        svc.dm_visible = lambda peer_id: peer_id == peer
        phone_dm("IN-D")
        for _ in range(3):
            await _aio.sleep(0)
        check("incoming DM in a visible, focused tab is read at once",
              _receipt_ids(reader.new_plaintexts()) == ["IN-D"])

    _aio.run(run())


def _kick_logged(peer_hex):
    """True if DM_HS_KICK for this peer prefix is in the debug log (peer ids are random per run)."""
    from bitchat_cli.debuglog import LOG_PATH
    with open(LOG_PATH, "rb") as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 262144))
        tail = f.read().decode("utf-8", errors="replace")
    return f"DM_HS_KICK: peer={peer_hex[:8]}" in tail


def test_no_handshake_until_peer_is_visible():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        svc.state.peer_nicknames.pop(phone.peer_hex)  # key known, peer not visible
        msg_id = await svc.send_private_message(phone.peer_hex, "queued")
        for _ in range(120):  # two minutes of 1 s ticks
            await svc._outbox_tick()
            await _aio.sleep(0)
            clock.advance(1)
        check("peer not in peer_nicknames: no handshake across 120 ticks",
              svc.handshake_packets() == [])
        check("its DM stays sending", svc._outbox[msg_id]["state"] == "sending")
        svc.state.set_peer(phone.peer_hex, "bob")  # peer becomes visible
        before = len(svc.handshake_packets())
        await svc._outbox_tick()
        await _aio.sleep(0)
        check("first tick after the peer appears (past backoff) starts a handshake",
              len(svc.handshake_packets()) == before + 1)
        check("that kick is logged as DM_HS_KICK", _kick_logged(phone.peer_hex))

    _aio.run(run())


def test_outbox_keeps_200_records_and_ignores_late_receipts():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        ids = []
        for i in range(250):
            mid = await svc.send_private_message(phone.peer_hex, f"m{i}")
            ids.append(mid)
            _phone_to_service(svc, phone, _ack(0x03, mid))  # delivered before the next send
        mine = [m for m, e in svc._outbox.items() if e["peer_id"] == phone.peer_hex]
        check("250 acked DMs leave 200 records", len(mine) == 200)
        check("the 200 kept are the most recent", mine == ids[-200:])
        check("oldest record dropped", ids[0] not in svc._outbox)

        lines_before = len(svc.lines)
        events_before = len(svc.dm_status_events)
        _phone_to_service(svc, phone, _ack(0x03, ids[0]))
        _phone_to_service(svc, phone, _ack(0x02, ids[0]))
        await _aio.sleep(0)
        check("late ack/receipt for a dropped id: no warning", len(svc.lines) == lines_before)
        check("late ack/receipt for a dropped id: no state event",
              len(svc.dm_status_events) == events_before)
        check("late receipt does not recreate the record", ids[0] not in svc._outbox)

    _aio.run(run())


def test_cap_never_drops_sending_records():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        first = None
        for i in range(199):
            mid = await svc.send_private_message(phone.peer_hex, f"d{i}")
            first = first or mid
            _phone_to_service(svc, phone, _ack(0x03, mid))
        # Session gone: the next two DMs stay sending. 199 delivered + 2 sending = 201.
        saved = svc._noise_sessions.pop(phone.peer_hex)
        stuck = await svc.send_private_message(phone.peer_hex, "stuck")
        last = await svc.send_private_message(phone.peer_hex, "last")
        mine = [m for m, e in svc._outbox.items() if e["peer_id"] == phone.peer_hex]
        check("cap holds at 200", len(mine) == 200)
        check("oldest delivered record dropped instead", first not in svc._outbox)
        check("sending DM is never dropped by the cap",
              stuck in svc._outbox and svc._outbox[stuck]["state"] == "sending")
        check("second sending DM also kept",
              last in svc._outbox and svc._outbox[last]["state"] == "sending")
        svc._noise_sessions[phone.peer_hex] = saved
        await svc._outbox_tick()
        await _aio.sleep(0)
        check("with the session back, the queued DMs flush",
              svc._outbox[stuck]["state"] == "sent" and svc._outbox[last]["state"] == "sent")

    _aio.run(run())


def test_unread_incoming_capped_at_500_per_peer():
    clock = FakeClock()

    async def run():
        svc, phone = _make(clock)
        await _establish(svc, phone)
        for i in range(600):
            mid = f"IN-{i:04d}"
            tlv = bytes([0x00, len(mid)]) + mid.encode() + bytes([0x01, 2]) + b"hi"
            _phone_to_service(svc, phone, bytes([0x01]) + tlv)
        for _ in range(3):
            await _aio.sleep(0)
        unread = svc._unread_incoming[phone.peer_hex]
        check("600 incoming DMs leave 500 unread ids", len(unread) == 500)
        check("kept ids are the newest 500",
              unread == [f"IN-{i:04d}" for i in range(100, 600)])

    _aio.run(run())


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
        test_dm_sent_once_never_retransmitted,
        test_dm_delivery_states_never_downgrade,
        test_queued_dm_waits_for_handshake_and_backoff,
        test_queue_expiry_marks_failed_and_sends_nothing,
        test_incoming_dm_gets_real_delivery_ack,
        test_read_receipts_once_per_unread_message,
        test_no_handshake_until_peer_is_visible,
        test_outbox_keeps_200_records_and_ignores_late_receipts,
        test_cap_never_drops_sending_records,
        test_unread_incoming_capped_at_500_per_peer,
    ]
    for test in tests:
        print(f"{test.__name__}:")
        test()
    print(f"\nAll {passed} checks passed.")
