"""Create two independent persistent local identities; never auto-trust them."""

import argparse
from pathlib import Path
from protocol.identity import Identity, b64, private_write


def initialize(root: Path, names=("Alice", "Bob")):
    for name in names:
        identity = Identity(root / name, name)
        private_write(
            root / "contacts" / (name + ".json"),
            {"name": name, "public": b64(identity.public)},
        )
        print(f"{name}: {identity.fingerprint}")
    print(
        "Compare fingerprints from each client through a trusted channel. No contacts were automatically trusted."
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(".runtime"))
    p.add_argument(
        "--name", action="append", help="Repeat to create custom local identities"
    )
    a = p.parse_args()
    initialize(a.root, a.name or ("Alice", "Bob"))
