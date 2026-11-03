# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A fork of **bitchat-cli** (original: https://github.com/dearabhin/bitchat-cli) with significant enhancements. It is a Python CLI for **bitchat**, a serverless peer-to-peer chat over a Bluetooth LE mesh. Wire-compatible with the real app (https://github.com/permissionlesstech/bitchat) for **public/broadcast chat** and **private (Noise-encrypted) DMs**.

### What's implemented (beyond upstream)
- Noise_XX_25519_ChaChaPoly_SHA256 encrypted private messages (bidirectional DMs)
- Out-of-band peer verification (`/verify`, `/unverify`, persisted to `~/.bitchat/verified_peers.json`)
- Identity-change warnings when a peer reappears with new keys
- BlueZ D-Bus GATT client (`bluez_central.py`) replacing `bleak`
- GATT peripheral server (`peripheral.py`)
- Packet relay with dedup, jitter, TTL decrement, split-horizon (Phase 1)
- Peer signature verification (Phase 2)

### What's NOT implemented
- Multi-hop mesh relaying (gossip sync, Phase 4)
- Topology/source routing (Phase 5)
- BLE peripheral advertising (not discoverable when idle)

## Commands

The app lives in the `bitchat_cli/` package (installable; see `pyproject.toml`).

```bash
pip install -e .                  # editable install of cryptography, prompt-toolkit, noiseprotocol
bitchat-cli                       # (or `bitchat`, or `python -m bitchat_cli`) run the app; scans over BLE
python selftest.py                # offline protocol round-trip + signature tests (no BLE needed)
```

`selftest.py` is the only thing runnable without hardware; it imports the `bitchat_cli` package, so run it from the repo root. The app requires a working Bluetooth LE adapter — without one it starts, prints the logo, and reports that the scan could not start. `selftest.py` needs only `cryptography` (not `prompt-toolkit`), so it runs in CI/headless. Published to PyPI as `bitchat-cli`; version is single-sourced in `bitchat_cli/__init__.py`.

In-app slash commands: `/w` (list known peers by peer-ID → nickname), `/peers` (list peers with keys and verification status), `/dm <id> <msg>` (encrypted private message), `/verify <id>` (mark peer as verified), `/unverify <id>` (remove verification), `/name <nick>` (change nickname + re-announce), `/send <path>` (broadcast an image/voice note/file; alias `/file`), `/clear`, `/help`. Any non-slash input is broadcast publicly to connected peers.

## Architecture

Single-process asyncio app. `main.py` → random 8-byte peer ID + `user-xxxx` nickname → `ChatState` → `CLI.run()`.

- **`protocol.py`** — pure serialization, no I/O. The real bitchat wire format:
  - `BitchatPacket.encode()/decode()`: big-endian header `version(1) type(1) ttl(1) timestamp_ms(8) flags(1) payloadLen(2)` + `senderID(8)` + optional `recipientID(8)` + payload + optional `signature(64)`, then PKCS#7 `MessagePadding` to a block size (256/512/1024/2048). Decode also handles v2 (16-byte header, source-route hops it skips) and zlib-compressed inbound payloads.
  - `MessageType` opcodes match upstream: `ANNOUNCE=0x01`, `MESSAGE=0x02` (public, **unencrypted**), `LEAVE=0x03`, `NOISE_HANDSHAKE=0x10`, `NOISE_ENCRYPTED=0x11`, `FRAGMENT=0x20`, `FILE_TRANSFER=0x22` (media — see `media.py`).
  - `data_for_signing()`: canonical bytes the Ed25519 signature covers — the packet re-encoded with **signature=None and ttl=0** (TTL mutates during relay), padded. The transmitted padding is irrelevant to verification; the receiver reconstructs this canonical form from the decoded fields.
  - `AnnouncementPacket`: TLV (`0x01` nickname, `0x02` X25519 noise pubkey, `0x03` Ed25519 signing pubkey).
  - A **public message's payload is the raw UTF-8 content string** — NOT a TLV/structured blob. The sender nickname is resolved from its peer ID via the ANNOUNCE it sent earlier. `BitchatMessage` is just a local value object for chat history.
  - `FragmentReassembler` reassembles inbound `FRAGMENT` packets (`fragmentID(8) index(2) total(2) originalType(1) data`) into the original encoded inner packet, which is then decoded recursively.
- **`media.py`** — pure (no-I/O) media helpers, wire-compatible with upstream `BitchatFilePacket.swift`/`MimeType.swift`. `BitchatFilePacket` is the **TLV payload of a `FILE_TRANSFER` (0x22)** packet: `0x01` fileName (UInt16 len), `0x02` fileSize (len=4, UInt32), `0x03` mimeType (UInt16 len), `0x04` content (**UInt32 len**; decode tolerates legacy 2-byte). Hard cap **1 MiB** (`MAX_PAYLOAD_BYTES`); `encode()` returns `None` above it. MIME helpers map extension↔MIME↔category (`image`/`audio`/`file`) and the chat-bubble prefix each uses (`[image] `/`[voice] `/`[file] `). Upstream has **no video type** — video (e.g. `.mp4`) is sent as a generic `application/octet-stream` `[file]`. A public media message is a single signed `FILE_TRANSFER` packet with `recipientID=None` (no separate MESSAGE); each side derives the `prefix+filename` chat line locally.
- **`identity.py`** — `IdentityKeys`: per-session X25519 static key + Ed25519 signing key. Exposes raw 32-byte public keys (for ANNOUNCE) and `sign()`. Public chat is unencrypted, but the real app **drops public messages whose signature is missing/invalid**, so every outbound packet must be signed and we must ANNOUNCE our signing key first.
- **`ble_service.py`** — all Bluetooth I/O via BlueZ D-Bus. GATT client (`bluez_central.py`) and peripheral server (`peripheral.py`). Scans for bitchat service UUID, connects, exchanges packets. Handles relay, dedup, signature verification, Noise handshake/encryption. - **`bluez_central.py`** — BlueZ D-Bus GATT client (scanner + connection + characteristic discovery). - **`peripheral.py`** — GATT peripheral server for receiving connections.
- **`chat_state.py`** — `ChatState`: holds `IdentityKeys`, chat history, peers keyed by **8-byte peer-ID hex → nickname** (from ANNOUNCE, NOT BLE MAC), and the set of connected BLE addresses. Shared by reference into `CLI` and `BLEService`.
- **`cli.py`** — `prompt_toolkit` REPL. Owns the `BLEService` and passes it a `redraw_prompt` callback so the async BLE layer can print incoming messages without corrupting the input line (`patch_stdout()` in `run()`). `CLI.run()` launches `BLEService.run()` as a background task and loops on `prompt_async()` concurrently on the same event loop.

## Constraints / gotchas

- **BlueZ central + peripheral**: this client can both connect to and accept connections from bitchat peers. It is discoverable when the peripheral is running.
- **Signatures are mandatory** for public messages to be accepted (see `identity.py`). If you change `BitchatPacket.encode()` or `data_for_signing()`, re-run `selftest.py` — the signature test simulates the receiver's verification path.
- **Noise wire format**: DMs use `\x01\x00$<UUID>\x01<len><content>` where `<len>` is a single byte content length. Type bytes: `\x01`=DM, `\x02`=delivery receipt, `\x03`=read receipt.
- **Fingerprint** = SHA-256(noise_public_key), 64 hex chars. Peer ID = first 8 bytes (16 hex chars).
- **Identity persistence**: CLI identity stored in `~/.bitchat/identity.json`. Phone identity in OS keychain.
- **MTU**: transmitted packets are padded to ≥256 bytes, so a single BLE write relies on the ~512-byte MTU that bitchat peers negotiate. Against a peer that only negotiates a small MTU, large writes may fail.
- The bitchat UUIDs and opcodes were verified against upstream `BLEService.swift`, `BinaryProtocol.swift`, `MessageType.swift`, and `Packets.swift`. Re-verify there before changing any wire constant.
- Version single-sourced in `bitchat_cli/__init__.py`.
