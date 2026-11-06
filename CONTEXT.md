# bitchat-cli Fork — Project Context

## What this is
Python BLE mesh client for the bitchat protocol (fork of dearabhin/bitchat-cli).
Repo: github.com/truerymes-bit/bitchat-cli
Local: ~/bitchat-cli-fork
Version: 0.3.0
Language: Python 3.14, Fedora Linux

## What it does
- BLE mesh networking via BlueZ D-Bus (central + peripheral roles)
- Public broadcast chat with multi-hop relay
- Noise-encrypted private DMs (Noise_XX_25519_ChaChaPoly_SHA256)
- Out-of-band peer verification (Ed25519 signatures)
- Gossip sync (GCS filter catch-up)
- Source routing (v2 packets with HAS_ROUTE, BFS through confirmed edges)
- Topology tracking (confirmed/unconfirmed edges, direct peers)

## Key files
- ble_service.py — all Bluetooth I/O, relay, dedup, signatures, Noise, handshake
- protocol.py — packet encode/decode, AnnouncementPacket, FragmentReassembler
- chat_state.py — peer info, topology, verified peers, compute_route (BFS: None=no path/self, []=direct, list=intermediate hops)
- cli.py — TUI, commands (/peers, /dm, /route, /verify, /topology, /sync, /clear)
- identity.py — persistent identity (X25519 + Ed25519), atomic writes
- peripheral.py — GATT server + BLE advertisement
- bluez_central.py — BlueZ D-Bus GATT client (replaces bleak)
- sync/ — gossip sync package (packet_id, gcs_filter, request_sync, gossip_sync)

## Phases (all complete)
1. Relay — TTL decrement, split-horizon, dedup (LRU 2000 cap), jitter, fanout
2. Verification — Ed25519 signatures on signed packets, TOFU bootstrap
3. Noise — XX handshake, ChaCha20Poly1305 transport, /dm command
4. Gossip sync — GCS filter, REQUEST_SYNC, announce retention/pruning
5. Topology — TLV 0x04 neighbor gossip, confirmed edges, source routing v2

## Review fixes applied (commit 0ad38d1, 5558d56, 076f6c9)
- DM length byte: bytes([len]) not chr() (fixes 128+ byte DMs)
- Session replacement on phone restart (matches Android reference)
- Relay fragmentation + double-relay suppression
- _connect: single except branch (no permanent blacklist)
- Noise replay protection (_recv_window)
- Docs corrected (peripheral advertising IS implemented)

## Known remaining
- DM replay protection implemented but not tested on hardware
- Capability TLV 0x05 parsed but not used (no private media support)
- Not tested: MTU handling, gossip sync vs live phones, source routing under load
- Linux-only (BlueZ, no bleak)
- `send_routed_message` floods from the origin instead of unicasting to the first hop (deferred until BLE hardware testing)

## Android reference (PRIMARY SOURCE OF TRUTH)
~/bitchat-android — the official bitchat Android client, used by millions.
This is PROVEN, production software. The CLI fork should align with it whenever
possible. Protocol docs: docs/SOURCE_ROUTING.md, docs/sync.md, docs/ANNOUNCEMENT_GOSSIP.md,
docs/NOISE_PEER_ID_BINDING.md, docs/PRIVATE_MEDIA_V1.md.
When in doubt, check what Android does — it is the reference implementation.

## DM reliability fixes (commit 6739b99, 2026-11-05)
- #7: NoiseSession.created_at; send_private_message re-handshakes if session missing/unfinished/older than 15s, waits up to 8s, prints failure instead of silent loss
- #8: DM packet TTL changed from 0 to DEFAULT_TTL (7), matching Android relay behavior
- #9: background handshake retry loop — every 10s, max 6 attempts per peer, started after sync manager, cancelled on stop
- #11: per-link write lock in _broadcast + retry on BlueZ "In Progress" (3 retries, 50ms delay); prevents link drops from back-to-back writes
- #12: send announce before each DM (0.2s delay) so phones that dropped the peer show "cli_client" instead of "Unknown"
- #6: debuglog.py — verbose logging to ~/.bitchat/bitchat-debug.log (2MB cap, trims to newest ~1MB); HS, DM send/receive, peripheral write errors routed there
- File transfer disabled in send_file (prints "File transfer is currently disabled.") pending fragmentation/signature issue
- Read receipts (0x02): supported in protocol but disabled in CLI — no mailbox UI to mark messages as read; enable when mailbox system is built
- NOSTR transport: not implemented; BLE-only CLI
- Tested: all 3 phones (gs9, Fold7, S24) receive DMs reliably; sender name correct on S24
- Known: #10 applied (DM delivery ack retry). S24 wireless adb drops when screen turns off. File transfer disabled. Nostr not implemented.

## Commands
- bitchat / bitchat-quiet — run the client
- selftest.py — 52 checks, all pass
- /peers, /dm, /route, /verify, /topology, /sync, /clear, /w
