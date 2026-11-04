# identity.py
#
# Cryptographic identity for a bitchat session. Public chat is NOT encrypted,
# but every peer must ANNOUNCE two raw public keys and sign its packets so the
# real app will list it as a peer and accept its broadcasts:
#
#   * a static X25519 key  -> "noise" public key (used for the Noise handshake,
#                             which we don't implement; we only advertise it)
#   * an Ed25519 signing key -> signs each packet's canonical bytes
#
# This mirrors the key pair stored by NoiseEncryptionService in the Swift app.

import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw

IDENTITY_PATH = Path.home() / ".bitchat" / "identity.json"


class IdentityKeys:
    """Holds a session's X25519 static key and Ed25519 signing key.

    Keys are persisted to ~/.bitchat/identity.json so the peer ID (derived
    from the Noise public key) stays stable across restarts.  A new identity
    is generated only on first run (or if the file is missing/corrupt).
    """

    def __init__(self):
        self._static_key = None
        self._signing_key = None
        self._nickname = None
        self._load_or_generate()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _write_file(self, noise_hex: str, signing_hex: str,
                    nickname=None, chmod: bool = True):
        """Atomically persist identity (and optional nickname) to disk."""
        try:
            IDENTITY_PATH.parent.mkdir(parents=True, exist_ok=True)
            # Tighten directory permissions when possible.
            try:
                os.chmod(IDENTITY_PATH.parent, 0o700)
            except OSError:
                pass

            data = {
                "noise_private_key": noise_hex,
                "signing_private_key": signing_hex,
            }
            if nickname:
                data["nickname"] = nickname

            fd, tmp = tempfile.mkstemp(
                prefix=".identity.", dir=str(IDENTITY_PATH.parent))
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(data, f, indent=2)
                    f.write("\n")
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, IDENTITY_PATH)
                if chmod:
                    try:
                        os.chmod(IDENTITY_PATH, 0o600)
                    except OSError:
                        pass
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except (OSError, ValueError, TypeError):
            # Best-effort: keep keys in memory even if persistence fails.
            pass

    def _load_or_generate(self):
        data = None
        # ---- Try loading an existing identity ----
        try:
            with open(IDENTITY_PATH) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("identity file is not a JSON object")

            # Support both key naming conventions.
            noise_key = data.get("noise_private_key") or data.get("noise_priv")
            signing_key = (data.get("signing_private_key")
                           or data.get("signing_priv"))
            if not isinstance(noise_key, str) or not isinstance(signing_key, str):
                raise ValueError("keys must be hex strings")
            if not noise_key or not signing_key:
                raise ValueError("missing keys")

            noise_priv = bytes.fromhex(noise_key)
            signing_priv = bytes.fromhex(signing_key)
            if len(noise_priv) != 32 or len(signing_priv) != 32:
                raise ValueError("keys must be 32 bytes")

            self._static_key = x25519.X25519PrivateKey.from_private_bytes(
                noise_priv)
            self._signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                signing_priv)

            self._nickname = data.get("nickname")
            if self._nickname is not None and not isinstance(self._nickname, str):
                self._nickname = str(self._nickname)
            if self._nickname == "":
                self._nickname = None

            # Migrate to the new key naming if an old-format file was loaded,
            # preserving any nickname that was already stored.
            old_format = ("noise_private_key" not in data
                          or "signing_private_key" not in data)
            if old_format:
                self._write_file(noise_priv.hex(), signing_priv.hex(),
                                 nickname=data.get("nickname"))
            else:
                # Enforce restrictive permissions on existing files.
                try:
                    os.chmod(IDENTITY_PATH, 0o600)
                except OSError:
                    pass
                try:
                    os.chmod(IDENTITY_PATH.parent, 0o700)
                except OSError:
                    pass
            return
        except (FileNotFoundError, KeyError, ValueError, TypeError,
                json.JSONDecodeError, OSError, AttributeError):
            pass

        # ---- Generate a new identity ----
        self._static_key = x25519.X25519PrivateKey.generate()
        self._signing_key = ed25519.Ed25519PrivateKey.generate()

        # Preserve any nickname stored in an existing (possibly corrupt) file.
        existing_nick = None
        try:
            if isinstance(data, dict):
                existing_nick = data.get("nickname")
            elif IDENTITY_PATH.exists():
                with open(IDENTITY_PATH) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    existing_nick = loaded.get("nickname")
        except (FileNotFoundError, json.JSONDecodeError, OSError,
                AttributeError, TypeError, ValueError):
            existing_nick = None

        if existing_nick:
            existing_nick = str(existing_nick)
        else:
            existing_nick = None

        self._nickname = existing_nick
        self._write_file(
            self._static_key.private_bytes_raw().hex(),
            self._signing_key.private_bytes_raw().hex(),
            nickname=existing_nick,
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def noise_public_key_bytes(self) -> bytes:
        """Raw 32-byte X25519 public key for the ANNOUNCE packet."""
        return self._static_key.public_key().public_bytes(
            encoding=_RAW, format=_RAW_PUB
        )

    def signing_public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key for the ANNOUNCE packet."""
        return self._signing_key.public_key().public_bytes(
            encoding=_RAW, format=_RAW_PUB
        )

    def noise_private_key_bytes(self) -> bytes:
        """Raw 32-byte X25519 private key."""
        return self._static_key.private_bytes_raw()

    @property
    def nickname(self) -> str:
        """Load nickname from identity.json, default 'cli_client'."""
        try:
            with open(IDENTITY_PATH) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                val = loaded.get("nickname")
                if val:
                    return str(val)
        except (FileNotFoundError, json.JSONDecodeError, OSError,
                AttributeError, TypeError, ValueError):
            pass
        if self._nickname:
            return str(self._nickname)
        return "cli_client"

    def save_nickname(self, nickname: str):
        """Persist a nickname to identity.json without clobbering keys."""
        data = {}
        if IDENTITY_PATH.exists():
            try:
                with open(IDENTITY_PATH) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, json.JSONDecodeError, AttributeError,
                    TypeError, ValueError):
                data = {}

        noise_hex = data.get("noise_private_key") or data.get("noise_priv") \
            if isinstance(data, dict) else None
        signing_hex = None
        if isinstance(data, dict):
            signing_hex = (data.get("signing_private_key")
                           or data.get("signing_priv"))

        if not isinstance(noise_hex, str) or not noise_hex:
            assert self._static_key is not None
            noise_hex = self._static_key.private_bytes_raw().hex()
        if not isinstance(signing_hex, str) or not signing_hex:
            assert self._signing_key is not None
            signing_hex = self._signing_key.private_bytes_raw().hex()

        self._nickname = nickname
        self._write_file(noise_hex, signing_hex, nickname=nickname)

    def sign(self, data: bytes) -> bytes:
        """Ed25519 signature (64 bytes) over the packet's canonical bytes."""
        return self._signing_key.sign(data)
