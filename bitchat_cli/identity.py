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
        self._load_or_generate()

    def _load_or_generate(self):
        # Try loading from disk
        try:
            with open(IDENTITY_PATH) as f:
                data = json.load(f)
            # Support both key naming conventions
            noise_key = data.get("noise_private_key") or data.get("noise_priv")
            signing_key = data.get("signing_private_key") or data.get("signing_priv")
            if not noise_key or not signing_key:
                raise ValueError("missing keys")
            noise_priv = bytes.fromhex(noise_key)
            signing_priv = bytes.fromhex(signing_key)
            self._static_key = x25519.X25519PrivateKey.from_private_bytes(noise_priv)
            self._signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_priv)
            # Migrate to new format if needed
            if "noise_private_key" not in data:
                try:
                    with open(IDENTITY_PATH, "w") as f:
                        json.dump({
                            "noise_private_key": noise_priv.hex(),
                            "signing_private_key": signing_priv.hex(),
                        }, f, indent=2)
                    os.chmod(IDENTITY_PATH, 0o600)
                except OSError:
                    pass
            return
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError, OSError):
            pass

        # Generate new keys
        self._static_key = x25519.X25519PrivateKey.generate()
        self._signing_key = ed25519.Ed25519PrivateKey.generate()

        # Preserve any existing nickname
        existing_nick = None
        try:
            with open(IDENTITY_PATH) as f:
                existing_nick = json.load(f).get("nickname")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

        # Persist to disk
        try:
            IDENTITY_PATH.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "noise_private_key": self._static_key.private_bytes_raw().hex(),
                "signing_private_key": self._signing_key.private_bytes_raw().hex(),
            }
            if existing_nick:
                data["nickname"] = existing_nick
            with open(IDENTITY_PATH, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(IDENTITY_PATH, 0o600)
        except OSError:
            pass

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
                return json.load(f).get("nickname", "cli_client")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "cli_client"

    def sign(self, data: bytes) -> bytes:
        """Ed25519 signature (64 bytes) over the packet's canonical bytes."""
        return self._signing_key.sign(data)
