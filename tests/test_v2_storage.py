"""Authenticated local persistence never restores live protocol state."""

from __future__ import annotations
import json

import pytest

from client.storage import LocalStore, atomic_private_write, read_private
from crypto.primitives import signature_keypair
from protocol.identity import Identity, b64, private_write, safety_number


@pytest.fixture(autouse=True)
def password_setting(monkeypatch):
    monkeypatch.delenv("CRYTOSAGE_STORAGE_PASSWORD", raising=False)


def message(**extra):
    return {
        "id": "one",
        "direction": "sent",
        "text": "Private message — नमस्ते",
        "time": "2026-11-07T14:00:00+00:00",
        "peer": "Bob",
        "status": "delivered",
        **extra,
    }


def test_history_encrypted_roundtrip_and_allowlist(tmp_path):
    store = LocalStore(tmp_path / "alice")
    store.save_history(
        [
            message(
                secret="do-not-store",
                session_id="do-not-store",
                packet={"ciphertext": "no"},
            )
        ]
    )
    raw = (tmp_path / "alice/history.json").read_bytes()
    assert b"Private message" not in raw and b"do-not-store" not in raw
    history = LocalStore(tmp_path / "alice").load_history()
    assert history == [message()]
    assert store.protection == "filesystem"
    assert (tmp_path / "alice/.keystore/master.key").stat().st_mode & 0o077 == 0
    assert (tmp_path / "alice/.keystore").stat().st_mode & 0o077 == 0


def test_bounded_history_and_invalid_message_shapes(tmp_path):
    store = LocalStore(tmp_path)
    store.save_history([message(id=str(i)) for i in range(510)])
    assert len(store.load_history()) == 500
    assert store.load_history()[0]["id"] == "10"
    with pytest.raises(ValueError, match="metadata"):
        store.save_history([message(error=None)])
    with pytest.raises(ValueError, match="message"):
        store.save_history([message(text="x" * 16385)])


def test_storage_tampering_never_silently_resets_history(tmp_path):
    store = LocalStore(tmp_path)
    store.save_history([message()])
    path = tmp_path / "history.json"
    payload = json.loads(path.read_text())
    payload["ciphertext"] = payload["ciphertext"][:-6] + "AAAAAA"
    private_write(path, payload)
    with pytest.raises(ValueError, match="authentication failed"):
        store.load_history()
    assert path.exists()


def test_wrong_master_key_rejects_existing_history(tmp_path):
    LocalStore(tmp_path).save_history([message()])
    atomic_private_write(tmp_path / ".keystore/master.key", b"x" * 32)
    with pytest.raises(ValueError, match="authentication failed"):
        LocalStore(tmp_path).load_history()


def test_passphrase_storage_requires_original_password(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYTOSAGE_STORAGE_PASSWORD", "long-enough-test-password")
    store = LocalStore(tmp_path)
    store.save_history([message()])
    assert store.protection == "passphrase"
    assert not (tmp_path / ".keystore/master.key").exists()
    assert LocalStore(tmp_path).load_history() == [message()]
    monkeypatch.setenv("CRYTOSAGE_STORAGE_PASSWORD", "wrong-but-long-password")
    with pytest.raises(ValueError, match="authentication failed"):
        LocalStore(tmp_path).load_history()
    monkeypatch.delenv("CRYTOSAGE_STORAGE_PASSWORD")
    with pytest.raises(ValueError, match="protection mode changed"):
        LocalStore(tmp_path)


def test_enabling_password_on_filesystem_store_requires_explicit_migration(
    tmp_path, monkeypatch
):
    LocalStore(tmp_path).save_history([message()])
    monkeypatch.setenv("CRYTOSAGE_STORAGE_PASSWORD", "long-enough-test-password")
    with pytest.raises(ValueError, match="protection mode changed"):
        LocalStore(tmp_path)


def test_password_minimum_does_not_create_usable_keystore(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYTOSAGE_STORAGE_PASSWORD", "short")
    with pytest.raises(ValueError, match="at least 12"):
        LocalStore(tmp_path)
    assert not (tmp_path / ".keystore/config.json").exists()


def test_v1_identity_migration_preserves_keys_and_pins(tmp_path):
    public, secret = signature_keypair()
    data = {"name": "Alice", "public": b64(public), "secret": b64(secret)}
    private_write(tmp_path / "identity.json", data)
    private_write(tmp_path / "trust.json", {"Bob": "a" * 64})
    alice = Identity(tmp_path, "Alice")
    assert alice.public == public and alice._secret == secret
    assert alice.trusted == {"Bob": "a" * 64}
    envelope = json.loads((tmp_path / "identity.json").read_text())
    assert envelope["format"] == "crytosage-local-v2"
    assert (
        "secret" not in envelope
        and b64(secret) not in (tmp_path / "identity.json").read_text()
    )
    restarted = Identity(tmp_path, "Alice")
    assert restarted.public == public and restarted._secret == secret
    assert restarted.storage_protection == "filesystem"


def test_invalid_v1_keypair_is_not_migrated(tmp_path):
    public, _ = signature_keypair()
    _, secret = signature_keypair()
    data = {"name": "Alice", "public": b64(public), "secret": b64(secret)}
    private_write(tmp_path / "identity.json", data)
    with pytest.raises(ValueError, match="do not match"):
        Identity(tmp_path, "Alice")
    assert json.loads((tmp_path / "identity.json").read_text()) == data


def test_identity_secret_and_history_have_distinct_authenticated_purposes(tmp_path):
    Identity(tmp_path, "Alice")
    (tmp_path / "history.json").write_bytes((tmp_path / "identity.json").read_bytes())
    (tmp_path / "history.json").chmod(0o600)
    with pytest.raises(ValueError, match="purpose"):
        LocalStore(tmp_path).load_history()


@pytest.mark.parametrize(
    "pin", [[], {"Bob": 1}, {"../Bob": "a" * 64}, {"Bob": "invalid"}]
)
def test_malformed_trust_is_rejected(tmp_path, pin):
    private_write(tmp_path / "trust.json", pin)
    with pytest.raises(ValueError):
        Identity(tmp_path, "Alice")


def test_explicit_identity_replacement_requires_both_fingerprints(tmp_path):
    alice = Identity(tmp_path / "alice", "Alice")
    bob = Identity(tmp_path / "bob", "Bob")
    replacement = Identity(tmp_path / "replacement", "Bob")
    alice.pin("Bob", bob.public, bob.fingerprint)
    with pytest.raises(ValueError, match="Identity changed"):
        alice.pin("Bob", replacement.public, replacement.fingerprint)
    with pytest.raises(ValueError, match="previous fingerprint"):
        alice.pin(
            "Bob",
            replacement.public,
            replacement.fingerprint,
            replace=True,
            previous_fingerprint="f" * 64,
        )
    alice.pin(
        "Bob",
        replacement.public,
        replacement.fingerprint,
        replace=True,
        previous_fingerprint=bob.fingerprint,
    )
    assert (
        Identity(tmp_path / "alice", "Alice").trusted["Bob"] == replacement.fingerprint
    )
    with pytest.raises(ValueError, match="pinned fingerprint"):
        alice.check_peer("Bob", bob.public)


def test_safety_number_is_public_stable_and_identity_specific(tmp_path):
    a, b = Identity(tmp_path / "a", "Alice"), Identity(tmp_path / "b", "Bob")
    assert a.safety_number == safety_number(a.public)
    assert len(a.safety_number.replace(" ", "")) == 78
    assert a.safety_number != b.safety_number


@pytest.mark.parametrize(
    "kind", ["identity", "history", "master", "config", "directory", "keystore"]
)
def test_symlink_storage_paths_rejected(tmp_path, kind):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    root = tmp_path / "alice"
    root.mkdir(mode=0o700)
    if kind == "directory":
        root.rmdir()
        root.symlink_to(outside, target_is_directory=True)
    elif kind == "keystore":
        (root / ".keystore").symlink_to(outside, target_is_directory=True)
    else:
        store = LocalStore(root)
        target = outside / "target"
        private_write(target, {"secret": "do not overwrite"})
        path = {
            "identity": root / "identity.json",
            "history": root / "history.json",
            "master": root / ".keystore/master.key",
            "config": root / ".keystore/config.json",
        }[kind]
        path.unlink(missing_ok=True)
        path.symlink_to(target)
    with pytest.raises(ValueError):
        if kind == "identity":
            Identity(root, "Alice")
        elif kind == "history":
            store.load_history()
        else:
            LocalStore(root)
    if (outside / "target").exists():
        assert json.loads((outside / "target").read_text()) == {
            "secret": "do not overwrite"
        }


def test_permissive_store_directory_and_key_are_rejected(tmp_path):
    root = tmp_path / "alice"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(ValueError, match="permissions"):
        LocalStore(root)
    root.chmod(0o700)
    LocalStore(root)
    (root / ".keystore/master.key").chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        LocalStore(root)


def test_atomic_write_preserves_existing_file_when_symlink_target_rejected(tmp_path):
    target = tmp_path / "actual.json"
    private_write(target, {"original": True})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        private_write(link, {"original": False})
    assert json.loads(read_private(target)) == {"original": True}


def test_keychain_backed_profile_has_no_master_file(tmp_path, monkeypatch):
    items = {}

    def item(account, *, create=False, migrate=None):
        if create:
            items.setdefault(account, b"k" * 32)
        return items[account]

    monkeypatch.setattr("client.storage.master_key", item)
    alice = Identity(tmp_path, "Alice", storage_backend="keychain")
    alice.store.save_history([message()])
    restarted = Identity(tmp_path, "Alice")
    assert restarted.storage_protection == "keychain"
    assert restarted.fingerprint == alice.fingerprint
    assert restarted.store.load_history() == [message()]
    assert len(items) == 1
    assert not (tmp_path / ".keystore/master.key").exists()


def test_keychain_denial_fails_closed_even_with_filesystem_env(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise ValueError("Keychain access denied")

    monkeypatch.setattr("client.storage.master_key", deny)
    with pytest.raises(ValueError, match="Keychain access denied"):
        Identity(tmp_path, "Alice", storage_backend="keychain")
    with pytest.raises(ValueError, match="Keychain access denied"):
        Identity(tmp_path, "Alice")
    assert not (tmp_path / "identity.json").exists()
    assert not (tmp_path / ".keystore/master.key").exists()


def test_keychain_migration_can_resume_and_preserves_ciphertext(tmp_path, monkeypatch):
    alice = Identity(tmp_path / "Alice", "Alice")
    bob = Identity(tmp_path / "Bob", "Bob")
    alice.pin("Bob", bob.public, bob.fingerprint)
    alice.store.save_history([message()])
    paths = [
        alice.directory / name
        for name in (
            "identity.json",
            "history.json",
            "trust.json",
            ".keystore/master.key",
        )
    ]
    original = [path.read_bytes() for path in paths]
    items = {}

    def fail_after_copy(account, *, migrate, **kwargs):
        items[account] = migrate
        raise ValueError("Keychain read-back interrupted")

    monkeypatch.setattr("client.storage.master_key", fail_after_copy)
    with pytest.raises(ValueError, match="read-back interrupted"):
        alice.store.migrate_to_keychain()
    assert Identity(alice.directory, "Alice").storage_protection == "filesystem"
    assert [path.read_bytes() for path in paths] == original

    def resume(account, *, create=False, migrate=None):
        assert not create
        key = items[account]
        if migrate is not None:
            assert migrate == key
        return key

    monkeypatch.setattr("client.storage.master_key", resume)
    alice.store.migrate_to_keychain()
    restored = Identity(alice.directory, "Alice")
    assert restored.storage_protection == "keychain"
    assert restored.fingerprint == alice.fingerprint
    assert restored.trusted == {"Bob": bob.fingerprint}
    assert restored.store.load_history() == [message()]
    assert [path.read_bytes() for path in paths] == original


def test_missing_identity_with_existing_history_is_not_replaced(tmp_path):
    alice = Identity(tmp_path, "Alice")
    alice.store.save_history([message()])
    (tmp_path / "identity.json").unlink()
    with pytest.raises(ValueError, match="Local identity is missing"):
        Identity(tmp_path, "Alice")
    assert not (tmp_path / "identity.json").exists()
    assert alice.store.load_history() == [message()]


def test_existing_encrypted_identity_does_not_get_a_replacement_keystore(tmp_path):
    Identity(tmp_path, "Alice")
    config = tmp_path / ".keystore/config.json"
    original = (tmp_path / "identity.json").read_bytes()
    config.unlink()
    with pytest.raises(ValueError, match="configuration is missing"):
        Identity(tmp_path, "Alice")
    assert not config.exists()
    assert (tmp_path / "identity.json").read_bytes() == original


def test_profile_lock_rejects_second_writer_and_releases_after_exit(tmp_path):
    from client.storage import private_lock

    lock = tmp_path / ".client.lock"
    with private_lock(lock, "Profile busy"):
        with pytest.raises(ValueError, match="Profile busy"):
            with private_lock(lock, "Profile busy"):
                pytest.fail("Overlapping writer acquired the lock")
    with private_lock(lock, "Profile busy"):
        assert lock.stat().st_mode & 0o077 == 0
