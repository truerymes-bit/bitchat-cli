# Changelog

All notable changes to this fork are documented here.

## [0.3.0-fork] — Initial fork release

Fork of [bitchat-cli](https://github.com/dearabhin/bitchat-cli) v0.2.3 with significant enhancements to private messaging, verification, and transport.

### Added
- **Noise-encrypted DMs**: Bidirectional private messaging over Noise_XX_25519_ChaChaPoly_SHA256, wire-compatible with bitchat phones
- **Basic multi-hop relay**: TTL decrement, split-horizon, dedup cache, jitter, fanout subsetting (Phase 1)
- **Out-of-band verification**: `/verify` and `/unverify` commands, persisted to `~/.bitchat/verified_peers.json`
- **Identity-change warnings**: Alerts when a peer reappears with a new cryptographic identity
- **BlueZ D-Bus transport**: Replaced `bleak` with native BlueZ GATT client and peripheral server
- **Packet relay**: Dedup cache, jitter, TTL decrement, split-horizon (Phase 1)
- **Peer signature verification**: Ed25519 signature checks on all signed packet types (Phase 2)
- **Commands**: `/peers`, `/dm`, `/verify`, `/unverify`, `/sync`
- **Gossip sync (Phase 4)**: GCS filter sync for catch-up on missed messages and announcements
- **Wire format discovery**: Phone DM format `\x01\x00$<UUID>\x01<len><content>` with type bytes (DM/receipt/ACK)
- **README updates**: Reflects new capabilities, updated features list, commands table
- **CLAUDE.md**: Updated for fork context, new architecture, constraints
- **requirements.txt**: Removed `bleak`, added `noiseprotocol`

### Changed
- Transport: `bleak` → BlueZ D-Bus (central + peripheral)
- DM wire format: discovered and implemented phone's actual format
- `/peers` output: now shows fingerprint, signing key, noise session status, verification status
- Scope: no longer "central-only" — peripheral server included

### Fixed
- Peripheral WriteValue setter signature (removed `self` for 3-arg convention)
- TxPower property: changed from READ to READWRITE with no-op setter (BlueZ tries to set it during registration)
- TxPower property error: includes `AdvertisingIncludes.TX_POWER` in advertisement
- TxPower/bluez_peripheral print suppression (defense in depth)
- RSSI tracking and peer-switching (disabled — was dropping connected peers)
- Connect lock / RSSI filter reversion (was blocking discovery)
- Disconnect cooldown (30s) to break reconnect loops
- Peer ID derivation from Noise public key (was random, phones dropped packets) — restored after regression
- BlueZ write_gatt_char now raises on failure instead of swallowing errors
- BlueZ services property returns real characteristic state (was hardcoded)

### Phase 4 — Gossip Sync (implemented)
- **GCS filter sync**: Golomb-Coded Set filter sync protocol (REQUEST_SYNC 0x21) with phones
- **Packet ID**: SHA-256(type | senderID | timestamp | payload)[:16] for cross-peer comparison
- **GCS filter**: Golomb-Rice encoding, MSB-first bit packing, configurable size/FPR
- **Initial per-peer sync**: 5s after first ANNOUNCE from new peer, sends REQUEST_SYNC unicast
- **Periodic sync**: every 30s, broadcast to all neighbors, TTL=0 (local only)
- **Response handling**: responds with missing packets (announcements first, then messages in timestamp order)
- **Announcement retention**: stores latest announce per peer, 60s age-out, 15s prune cycle
- **LEAVE handling**: removes peer's announce from sync candidate set on departure
- **Commands**: `/sync` to manually trigger gossip sync
- **Interoperability**: wire format matches bitchat-android GCSFilter (h64 masked to 63-bit, (x-1) Golomb-Rice, zero→1 mapping)

### Phase 5 — Topology (complete)
- **Neighbor gossip (TLV 0x04)**: ANNOUNCE packets now include directly connected peer IDs
- **Mesh graph tracking**: topology dict with confirmed/unconfirmed edge detection
- **Source routing (v2)**: HAS_ROUTE flag, route list in packets, BFS path computation through confirmed edges
- **Relay-by-route**: source-routed packets are unicasted to the next hop (with flood fallback)
- **Commands**: `/topology` to display mesh graph, `/route <id> <msg>` to send via source-routed path

### Not yet implemented
- (none — all planned features implemented)

### Credits
- Original project: [bitchat-cli](https://github.com/dearabhin/bitchat-cli) by Abhin
- Wire format: [bitchat](https://github.com/permissionlesstech/bitchat) by permissionlesstech
- Backchat Rust reference: `/home/mwatters/quarantine/backchat-2026-10-29-0009/`