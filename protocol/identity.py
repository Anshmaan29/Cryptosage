"""Persistent local ML-DSA identities and explicit fingerprint pins."""

import base64
import hashlib
import json
import re
from pathlib import Path
from crypto.primitives import signature_keypair, sign, verify
from client.storage import LocalStore, atomic_private_write, read_private


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 200_000:
        raise ValueError("Invalid encoded field")
    return base64.b64decode(value, validate=True)


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def fingerprint(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()


def valid_name(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]{0,31}", name
    ):
        raise ValueError(
            "Identity name must be 1–32 letters, digits, underscores or hyphens"
        )
    return name


def private_write(path: Path, data: dict) -> None:
    atomic_private_write(Path(path), json.dumps(data, allow_nan=False).encode())


def safety_number(public: bytes) -> str:
    """Public comparison aid, not Signal's safety-number protocol."""
    number = str(int.from_bytes(hashlib.sha256(public).digest(), "big")).zfill(78)
    return " ".join(number[i : i + 6] for i in range(0, len(number), 6))


class Identity:
    def __init__(self, directory: Path, name: str):
        self.name = valid_name(name)
        self.directory = Path(directory)
        self._store = LocalStore(self.directory)
        self.storage_protection = self._store.protection
        path = self.directory / "identity.json"
        migrate = False
        if path.exists() or path.is_symlink():
            try:
                stored = json.loads(read_private(path))
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid stored identity") from exc
            if self._store.is_envelope(stored):
                data = self._store.read_secret(path, "identity")
            else:
                data, migrate = stored, True
            if not isinstance(data, dict) or set(data) != {"name", "public", "secret"}:
                raise ValueError("Invalid stored identity")
            if data["name"] != name:
                raise ValueError("Identity name does not match stored identity")
            self.public, self._secret = unb64(data["public"]), unb64(data["secret"])
            challenge = b"crytosage/local-identity-integrity/v2"
            if not verify(self.public, challenge, sign(self._secret, challenge)):
                raise ValueError("Stored identity public and private keys do not match")
        else:
            self.public, self._secret = signature_keypair()
            data = {
                "name": name,
                "public": b64(self.public),
                "secret": b64(self._secret),
            }
            migrate = True
        if migrate:
            self._store.write_secret(path, "identity", data)
        self.fingerprint = fingerprint(self.public)
        self.safety_number = safety_number(self.public)
        self.trust_path = self.directory / "trust.json"
        try:
            self.trusted = (
                json.loads(read_private(self.trust_path))
                if self.trust_path.exists() or self.trust_path.is_symlink()
                else {}
            )
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid stored contact trust") from exc
        if not isinstance(self.trusted, dict):
            raise ValueError("Invalid stored contact trust")
        for peer_name, pin in self.trusted.items():
            valid_name(peer_name)
            if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
                raise ValueError("Invalid stored contact fingerprint")

    def sign(self, value: dict) -> str:
        return b64(sign(self._secret, canonical(value)))

    def pin(
        self,
        name: str,
        public: bytes,
        expected_fingerprint: str,
        replace: bool = False,
        previous_fingerprint: str | None = None,
    ) -> None:
        valid_name(name)
        if not isinstance(expected_fingerprint, str) or type(replace) is not bool:
            raise ValueError("Invalid fingerprint verification input")
        expected = expected_fingerprint.lower().replace(" ", "").replace(":", "")
        actual = fingerprint(public)
        if actual != expected:
            raise ValueError("Fingerprint does not match the contact public key")
        old = self.trusted.get(name)
        if old and old != actual:
            if not replace or previous_fingerprint != old:
                raise ValueError(
                    "Identity changed; explicit replacement and previous fingerprint confirmation required"
                )
        self.trusted[name] = actual
        private_write(self.trust_path, self.trusted)

    def check_peer(self, name: str, public: bytes) -> None:
        valid_name(name)
        actual = self.trusted.get(name)
        if actual is None:
            raise ValueError(
                "Unverified contact: compare and pin the fingerprint first"
            )
        if actual != fingerprint(public):
            raise ValueError("Peer identity changed: pinned fingerprint mismatch")
