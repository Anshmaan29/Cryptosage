"""Authenticated local storage; live protocol keys are deliberately never persisted.

A password uses scrypt. Otherwise a random key is protected by local filesystem
permissions; copying the entire directory or compromising the same OS account
also exposes that key. This fallback is not a disk-theft security boundary.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "crytosage-local-v2"
MAX_ENVELOPE = 24_000_000
MAX_HISTORY = 500
HISTORY_FIELDS = {
    "id",
    "direction",
    "text",
    "time",
    "peer",
    "status",
    "error",
    "delivered_at",
}


def protected_directory(path: Path) -> None:
    """Require a private, owned directory and never follow its own symlink."""
    if path.is_symlink():
        raise ValueError("Local storage directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError(
            "Local storage directory permissions must be 0700 and owned by this user"
        )


def read_private(path: Path, limit: int = MAX_ENVELOPE) -> bytes:
    """Open without following symlinks, then check the opened file, not its path."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("Local private file cannot be safely opened") from exc
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError(
                "Local private file permissions must be 0600 and owned by this user"
            )
        if info.st_size > limit:
            raise ValueError("Local storage file exceeds its size limit")
        value = handle.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Local storage file exceeds its size limit")
        return value


def atomic_private_write(path: Path, raw: bytes) -> None:
    protected_directory(path.parent)
    if path.is_symlink():
        raise ValueError("Local private file must not be a symlink")
    if path.exists():
        read_private(path)
    temporary = path.parent / ("." + path.name + "." + secrets.token_hex(12) + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _create_once(path: Path, raw: bytes) -> None:
    """Race-safe keystore initialization shared by identity and history readers."""
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        return
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Invalid local storage envelope")
    return base64.b64decode(value, validate=True)


class LocalStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        protected_directory(self.directory)
        self.keystore = self.directory / ".keystore"
        protected_directory(self.keystore)
        password = os.environ.get("CRYTOSAGE_STORAGE_PASSWORD")
        if password is not None and len(password) < 12:
            raise ValueError("Storage password must contain at least 12 characters")
        config_path = self.keystore / "config.json"
        config = {
            "version": 1,
            "protection": "passphrase" if password is not None else "filesystem",
            "salt": _encode(secrets.token_bytes(16)),
        }
        _create_once(config_path, json.dumps(config).encode())
        try:
            config = json.loads(read_private(config_path, 2048))
            self.protection = config["protection"]
            salt = _decode(config["salt"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid local keystore configuration") from exc
        if (
            config.get("version") != 1
            or len(salt) != 16
            or self.protection not in {"filesystem", "passphrase"}
        ):
            raise ValueError("Invalid local keystore configuration")
        if (password is not None) != (self.protection == "passphrase"):
            raise ValueError(
                "Storage protection mode changed; use the original password setting, do not reset the keystore"
            )
        if self.protection == "passphrase":
            self._key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
                password.encode()
            )
        else:
            key_path = self.keystore / "master.key"
            _create_once(key_path, secrets.token_bytes(32))
            self._key = read_private(key_path, 32)
            if len(self._key) != 32:
                raise ValueError("Invalid local storage master key")

    def _aad(self, purpose: str) -> bytes:
        return (FORMAT + "\0" + purpose + "\0" + self.protection).encode()

    def is_envelope(self, data: Any) -> bool:
        return isinstance(data, dict) and data.get("format") == FORMAT

    def read_secret(self, path: Path, purpose: str) -> Any:
        try:
            envelope = json.loads(read_private(path))
            if (
                not self.is_envelope(envelope)
                or envelope.get("purpose") != purpose
                or envelope.get("protection") != self.protection
            ):
                raise ValueError("Invalid local storage envelope or purpose")
            nonce, ciphertext = (
                _decode(envelope["nonce"]),
                _decode(envelope["ciphertext"]),
            )
            if len(nonce) != 12 or len(ciphertext) < 16:
                raise ValueError("Invalid local storage ciphertext length")
            plain = AESGCM(self._key).decrypt(nonce, ciphertext, self._aad(purpose))
            return json.loads(plain)
        except (
            InvalidTag,
            KeyError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(
                "Local storage authentication failed; incorrect password/key or damaged data"
            ) from exc

    def write_secret(self, path: Path, purpose: str, value: Any) -> None:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(raw) > MAX_ENVELOPE // 2:
            raise ValueError("Local storage payload exceeds its size limit")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, raw, self._aad(purpose))
        envelope = {
            "format": FORMAT,
            "purpose": purpose,
            "protection": self.protection,
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }
        # Verify the envelope before replacing any previous plaintext migration file.
        if AESGCM(self._key).decrypt(nonce, ciphertext, self._aad(purpose)) != raw:
            raise ValueError("Local storage encryption verification failed")
        atomic_private_write(path, json.dumps(envelope, sort_keys=True).encode())
        if self.read_secret(path, purpose) != value:
            raise ValueError("Local storage read-back verification failed")

    def load_history(self) -> list[dict]:
        path = self.directory / "history.json"
        if not path.exists() and not path.is_symlink():
            return []
        history = self.read_secret(path, "history")
        if not isinstance(history, list) or len(history) > MAX_HISTORY:
            raise ValueError("Invalid stored conversation history")
        return self._history(history)

    def _history(self, messages: list[dict]) -> list[dict]:
        if not isinstance(messages, list):
            raise ValueError("Conversation history must be a list")
        clean = []
        for row in messages[-MAX_HISTORY:]:
            if not isinstance(row, dict):
                raise ValueError("Invalid stored conversation message")
            item = {key: value for key, value in row.items() if key in HISTORY_FIELDS}
            if (
                item.get("direction") not in {"sent", "received"}
                or not isinstance(item.get("text"), str)
                or len(item["text"].encode()) > 16_384
                or not isinstance(item.get("peer"), str)
                or not isinstance(item.get("time"), str)
            ):
                raise ValueError("Invalid stored conversation message")
            if any(not isinstance(value, str) for value in item.values()):
                raise ValueError("Invalid stored conversation metadata")
            clean.append(item)
        return clean

    def save_history(self, messages: list[dict]) -> None:
        self.write_secret(
            self.directory / "history.json", "history", self._history(messages)
        )
