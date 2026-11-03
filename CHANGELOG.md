# Changelog

All notable changes to this fork are documented here.

## [0.3.0-fork] — Initial fork release

Fork of [bitchat-cli](https://github.com/dearabhin/bitchat-cli) v0.2.3 with significant enhancements to private messaging, verification, and transport.

### Added
- **Noise-encrypted DMs**: Bidirectional private messaging over Noise_XX_25519_ChaChaPoly_SHA256, wire-compatible with bitchat phones
- **Out-of-band verification**: `/verify` and `/unverify` commands, persisted to `~/.bitchat/verified_peers.json`
- **Identity-change warnings**: Alerts when a peer reappears with a new cryptographic identity
- **BlueZ D-Bus transport**: Replaced `bleak` with native BlueZ GATT client and peripheral server
- **Packet relay**: Dedup cache, jitter, TTL decrement, split-horizon (Phase 1)
- **Peer signature verification**: Ed25519 signature checks on all signed packet types (Phase 2)
- **Commands**: `/peers`, `/dm`, `/verify`, `/unverify`
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
- TxPower property error suppression
- RSSI tracking and peer-switching (disabled — was dropping connected peers)
- Connect lock / RSSI filter reversion (was blocking discovery)
- Disconnect cooldown (30s) to break reconnect loops
- Peer ID derivation from Noise public key (was random, phones dropped packets)
- ANNOUNCE throttle and announce-on-connect

### Not yet implemented
- Phase 4: Gossip sync for missed messages
- Phase 5: Topology/source routing for multi-hop delivery
- BLE peripheral advertising (discoverable when idle)

### Credits
- Original project: [bitchat-cli](https://github.com/dearabhin/bitchat-cli) by Abhin
- Wire format: [bitchat](https://github.com/permissionlesstech/bitchat) by permissionlesstech
- Backchat Rust reference: `/home/mwatters/quarantine/backchat-2026-10-29-0009/`