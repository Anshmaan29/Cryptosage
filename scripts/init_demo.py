"""Create two independent persistent local identities; never auto-trust them."""

import argparse
from pathlib import Path
from protocol.identity import Identity, b64, private_write, valid_name
from client.storage import LocalStore, private_lock


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
    p.add_argument(
        "--migrate-to-keychain",
        action="store_true",
        help="Copy an existing profile key to Keychain; retain the original key file",
    )
    a = p.parse_args()
    if a.migrate_to_keychain:
        if not a.name:
            p.error("Choose the existing profile with --name and stop its client first")
        for name in a.name:
            profile = a.root / valid_name(name)
            if not (profile / ".keystore/config.json").is_file():
                p.error("Migration requires an existing profile")
            with private_lock(
                profile / ".client.lock", "Stop this client before migrating its key"
            ):
                LocalStore(profile).migrate_to_keychain()
            print(
                f"{name}: Keychain backend selected. Original key file retained for recovery."
            )
    else:
        initialize(a.root, a.name or ("Alice", "Bob"))
