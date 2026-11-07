"""Persistent local ML-DSA identities and explicit fingerprint pins."""
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from crypto.primitives import signature_keypair, sign


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def unb64(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 200_000:
        raise ValueError('Invalid encoded field')
    return base64.b64decode(value, validate=True)


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def fingerprint(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()


def valid_name(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', name):
        raise ValueError('Identity name must be 1–32 letters, digits, underscores or hyphens')
    return name


def private_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f)
    os.chmod(temp, 0o600)
    os.replace(temp, path)


class Identity:
    def __init__(self, directory: Path, name: str):
        self.name = valid_name(name)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.directory / 'identity.json'
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise ValueError('Identity file permissions must be 0600')
            data = json.loads(path.read_text())
            if data['name'] != name:
                raise ValueError('Identity name does not match stored identity')
            self.public, self._secret = unb64(data['public']), unb64(data['secret'])
        else:
            self.public, self._secret = signature_keypair()
            private_write(path, {'name': name, 'public': b64(self.public), 'secret': b64(self._secret)})
        self.fingerprint = fingerprint(self.public)
        self.trust_path = self.directory / 'trust.json'
        self.trusted = json.loads(self.trust_path.read_text()) if self.trust_path.exists() else {}

    def sign(self, value: dict) -> str:
        return b64(sign(self._secret, canonical(value)))

    def pin(self, name: str, public: bytes, expected_fingerprint: str) -> None:
        valid_name(name)
        expected = expected_fingerprint.lower().replace(' ', '').replace(':', '')
        actual = fingerprint(public)
        if actual != expected:
            raise ValueError('Fingerprint does not match the contact public key')
        old = self.trusted.get(name)
        if old and old != actual:
            raise ValueError('Identity changed; remove the old trust entry offline after verification')
        self.trusted[name] = actual
        private_write(self.trust_path, self.trusted)

    def check_peer(self, name: str, public: bytes) -> None:
        valid_name(name)
        actual = self.trusted.get(name)
        if actual is None:
            raise ValueError('Unverified contact: compare and pin the fingerprint first')
        if actual != fingerprint(public):
            raise ValueError('Peer identity changed: pinned fingerprint mismatch')
