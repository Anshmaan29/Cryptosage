"""Strict adapters around liboqs; no fallback or simulated cryptography."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import sys
from contextlib import redirect_stdout
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "HQC-1", "HQC-3", "HQC-5")
SIGNATURE = "ML-DSA-65"


class CryptoError(ValueError):
    """Rejected unavailable algorithms, malformed input, or failed integrity."""


@lru_cache(maxsize=1)
def _oqs() -> Any:
    prefix = Path(
        os.environ.get(
            "OQS_INSTALL_PATH", Path(__file__).resolve().parents[1] / ".local"
        )
    )
    candidates = [*prefix.glob("lib/liboqs.*"), *prefix.glob("lib64/liboqs.*")]
    if not any(
        p.suffix in {".so", ".dylib", ".dll"} or ".so." in p.name for p in candidates
    ):
        # liboqs-python otherwise attempts an implicit source installation on import.
        raise CryptoError(
            "liboqs is unavailable; run scripts/setup_crypto.sh before starting"
        )
    os.environ.setdefault("OQS_INSTALL_PATH", str(prefix))
    # The upstream binding logs its import banner to stdout; reserve stdout for CLI JSON.
    with redirect_stdout(sys.stderr):
        import oqs
    if SIGNATURE not in oqs.get_enabled_sig_mechanisms():
        raise CryptoError("required ML-DSA-65 implementation is not enabled")
    return oqs


def _bytes(value: bytes, label: str, length: int | None = None) -> None:
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise CryptoError(
            f"invalid {label}"
            + (f" length (expected {length} bytes)" if length is not None else " type")
        )


def _kem(name: str, secret: bytes | None = None) -> Any:
    if name not in KEMS:
        raise CryptoError("unsupported KEM identifier")
    oqs = _oqs()
    if name not in oqs.get_enabled_kem_mechanisms():
        raise CryptoError(f"{name} implementation is unavailable")
    if secret is not None:
        with oqs.KeyEncapsulation(name) as probe:
            _bytes(secret, "KEM secret key", probe.details["length_secret_key"])
    return oqs.KeyEncapsulation(name, secret_key=secret)


def available_algorithms() -> list[dict[str, Any]]:
    """Report enabled KEMs and their levels from the native library."""
    oqs = _oqs()
    result = []
    for name in KEMS:
        if name not in oqs.get_enabled_kem_mechanisms():
            continue
        with _kem(name) as kem:
            d = kem.details
            result.append(
                {
                    "name": name,
                    "security_level": d["claimed_nist_level"],
                    "public_key_bytes": d["length_public_key"],
                    "secret_key_bytes": d["length_secret_key"],
                    "ciphertext_bytes": d["length_ciphertext"],
                    "shared_secret_bytes": d["length_shared_secret"],
                    "status": "experimental"
                    if name.startswith("HQC-")
                    else "recommended",
                    "implementation_version": d["version"],
                    "standardization": "FIPS 203"
                    if name.startswith("ML-KEM-")
                    else "Selected for future standardization; 2025-08-22 specification",
                }
            )
    return result


def kem_keypair(name: str) -> tuple[bytes, bytes]:
    with _kem(name) as kem:
        public = kem.generate_keypair()
        return public, kem.export_secret_key()


def encapsulate(name: str, public: bytes) -> tuple[bytes, bytes]:
    with _kem(name) as kem:
        _bytes(public, "KEM public key", kem.details["length_public_key"])
        try:
            return kem.encap_secret(public)
        except RuntimeError as exc:
            raise CryptoError("KEM encapsulation rejected input") from exc


def decapsulate(name: str, secret: bytes, ciphertext: bytes) -> bytes:
    with _kem(name, secret) as kem:
        _bytes(ciphertext, "KEM ciphertext", kem.details["length_ciphertext"])
        try:
            return kem.decap_secret(ciphertext)
        except RuntimeError as exc:
            raise CryptoError("KEM decapsulation rejected input") from exc


def signature_keypair() -> tuple[bytes, bytes]:
    with _oqs().Signature(SIGNATURE) as signer:
        public = signer.generate_keypair()
        return public, signer.export_secret_key()


def sign(secret: bytes, message: bytes) -> bytes:
    _bytes(message, "signature message")
    with _oqs().Signature(SIGNATURE) as probe:
        _bytes(secret, "signature secret key", probe.details["length_secret_key"])
    with _oqs().Signature(SIGNATURE, secret_key=secret) as signer:
        return signer.sign(message)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    with _oqs().Signature(SIGNATURE) as verifier:
        d = verifier.details
        if (
            not isinstance(public, bytes)
            or len(public) != d["length_public_key"]
            or not isinstance(signature, bytes)
            or len(signature) != d["length_signature"]
            or not isinstance(message, bytes)
        ):
            return False
        return verifier.verify(message, signature, public)


def hkdf(
    secret: bytes, info: bytes, length: int = 32, salt: bytes | None = None
) -> bytes:
    _bytes(secret, "HKDF input")
    _bytes(info, "HKDF domain")
    if not secret or not info or type(length) is not int or not 1 <= length <= 8160:
        raise CryptoError("invalid HKDF parameters")
    if salt is not None:
        _bytes(salt, "HKDF salt")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        secret
    )


AEADS: dict[str, type[AESGCM] | type[ChaCha20Poly1305]] = {
    "AES-256-GCM": AESGCM,
    "ChaCha20-Poly1305": ChaCha20Poly1305,
}
DEFAULT_AEAD = "AES-256-GCM"


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, *, aead: str = DEFAULT_AEAD
) -> bytes:
    _bytes(key, "AEAD key", 32)
    _bytes(nonce, "AEAD nonce", 12)
    _bytes(plaintext, "plaintext")
    _bytes(aad, "associated data")
    if aead not in AEADS:
        raise CryptoError("unsupported AEAD")
    return AEADS[aead](key).encrypt(nonce, plaintext, aad)


def decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, *, aead: str = DEFAULT_AEAD
) -> bytes:
    _bytes(key, "AEAD key", 32)
    _bytes(nonce, "AEAD nonce", 12)
    if aead not in AEADS:
        raise CryptoError("unsupported AEAD")
    _bytes(ciphertext, "ciphertext")
    _bytes(aad, "associated data")
    if len(ciphertext) < 16:
        raise CryptoError("invalid AEAD ciphertext length")
    try:
        return AEADS[aead](key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("ciphertext integrity verification failed") from exc


def versions() -> dict[str, str]:
    oqs = _oqs()
    return {
        "liboqs": oqs.oqs_version(),
        "liboqs_python": oqs.oqs_python_version(),
        "cryptography": importlib.metadata.version("cryptography"),
        "python": platform.python_version(),
        "signature": SIGNATURE,
        "liboqs_commit": "5a1a854b0dc9f2141bdc771c555ee60c37950183",
        "liboqs_python_commit": "64c76ad0a80d6c69f2003219eb27b253782a3d68",
    }
