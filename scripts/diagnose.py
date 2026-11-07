"""Check required capabilities without reading or printing credentials."""

from __future__ import annotations

import importlib.metadata
import platform
import shutil
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    print(
        f"Platform: {platform.system()} {platform.machine()} | Python {platform.python_version()}"
    )
    print(
        f"Project virtual environment active: {Path(sys.prefix).resolve() == (root / '.venv').resolve()}"
    )
    errors = []
    for command in ("git", "cc"):
        available = shutil.which(command) is not None
        print(f"{command}: {'available' if available else 'missing'}")
        if not available:
            errors.append(f"{command} is required for source installation")
    for package in (
        "fastapi",
        "websockets",
        "cryptography",
        "psutil",
        "pandas",
        "matplotlib",
        "pytest",
    ):
        try:
            print(f"{package}: {importlib.metadata.version(package)}")
        except importlib.metadata.PackageNotFoundError:
            errors.append(f"{package} is not installed")
    try:
        from crypto.primitives import (
            available_algorithms,
            decapsulate,
            encapsulate,
            kem_keypair,
            signature_keypair,
            sign,
            verify,
            versions,
        )

        print("Cryptographic versions:", versions())
        capabilities = available_algorithms()
        for algorithm in capabilities:
            name = algorithm["name"]
            public, secret = kem_keypair(name)
            ciphertext, shared = encapsulate(name, public)
            if decapsulate(name, secret, ciphertext) != shared:
                raise ValueError(f"{name}: actual KEM roundtrip failed")
            print(
                f"{name}: real roundtrip passed; level {algorithm['security_level']}; {algorithm['status']}"
            )
        if {a["name"] for a in capabilities} != {"ML-KEM-768", "HQC-3"}:
            errors.append(
                "Required level-3 KEM capability missing; run scripts/setup_crypto.sh"
            )
        public, secret = signature_keypair()
        if not verify(
            public,
            b"Crytosage dependency diagnosis",
            sign(secret, b"Crytosage dependency diagnosis"),
        ):
            raise ValueError("ML-DSA-65 verification failed")
        print("ML-DSA-65: real sign/verify passed")
    except (ImportError, ValueError, RuntimeError) as exc:
        errors.append(f"Cryptographic capability check: {exc}")
    for error in errors:
        print("FAILED:", error, file=sys.stderr)
    if not errors:
        print("Required dependency and real cryptographic checks passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
