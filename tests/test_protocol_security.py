"""Real protocol checks: assertions describe the expected security behavior."""

from copy import deepcopy
import time
import pytest
from crypto.primitives import hkdf, signature_keypair, sign
from protocol.identity import Identity, b64, canonical, unb64
from protocol.session import Peer, REKEY_AFTER, complete_handshake
from policy.engine import load_policy


def resign(identity, packet):
    packet["signature"] = identity.sign(
        {k: v for k, v in packet.items() if k != "signature"}
    )
    return packet


def test_four_flights_and_directional_chat(peers):
    alice, bob = peers
    result = complete_handshake(alice, bob)
    assert result["handshake_ms"] > 0 and result["handshake_bytes"] > 10_000
    assert alice.session.algorithm == bob.session.algorithm == "ML-KEM-768"
    assert alice.session.session_id == bob.session.session_id
    assert alice.session._send_chain == bob.session._receive_chain
    assert alice.session._send_chain != alice.session._receive_chain
    assert (
        bob.session.open(alice.session.seal("Hello Bob — नमस्ते")) == "Hello Bob — नमस्ते"
    )
    assert alice.session.open(bob.session.seal("Hello Alice")) == "Hello Alice"


def test_neither_side_usable_before_key_confirmation(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    response = bob.receive(offer)
    assert not alice.session and not bob.session
    finish = alice.receive(response)
    assert not alice.session and not bob.session
    ack = bob.receive(finish)
    assert bob.session and not alice.session
    alice.receive(ack)
    assert alice.session


def test_unknown_contact_rejected_despite_valid_signature(tmp_path):
    alice = Identity(tmp_path / "alice", "Alice")
    bob = Identity(tmp_path / "bob", "Bob")
    alice.pin("Bob", bob.public, bob.fingerprint)
    offer = Peer(alice, load_policy()).initiate("Bob")
    with pytest.raises(ValueError, match="Unverified contact"):
        Peer(bob, load_policy()).receive(offer)


def test_unverified_sender_cannot_initiate(tmp_path):
    peer = Peer(Identity(tmp_path, "Alice"), load_policy())
    with pytest.raises(ValueError, match="Unverified contact"):
        peer.initiate("Bob")


def test_identity_persistence_and_private_permissions(tmp_path):
    alice = Identity(tmp_path, "Alice")
    same = Identity(tmp_path, "Alice")
    assert alice.public == same.public and alice.fingerprint == same.fingerprint
    assert (tmp_path / "identity.json").stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="name"):
        Identity(tmp_path, "Mallory")
    (tmp_path / "identity.json").chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        Identity(tmp_path, "Alice")


def test_fingerprint_verification_and_changed_identity(peers):
    alice, bob = peers
    with pytest.raises(ValueError, match="does not match"):
        alice.identity.pin("Bob", bob.identity.public, "0" * 64)
    replacement, _ = signature_keypair()
    with pytest.raises(ValueError, match="Identity changed"):
        alice.identity.pin(
            "Bob", replacement, __import__("hashlib").sha256(replacement).hexdigest()
        )
    with pytest.raises(ValueError, match="identity changed"):
        alice.identity.check_peer("Bob", replacement)


@pytest.mark.parametrize("field", ["algorithms", "policy", "measurements"])
def test_offer_fields_are_signed(peers, field):
    alice, bob = peers
    offer = alice.initiate("Bob")
    if field == "algorithms":
        offer["offer"][field] = ["HQC-3"]
    elif field == "policy":
        offer["offer"][field]["minimum_security_level"] = 1
    else:
        offer["offer"][field] = {"ML-KEM-768": {"handshake_ms": 999}}
    with pytest.raises(ValueError, match="signature"):
        bob.receive(offer)
    assert bob.session is None


def test_downgraded_selected_algorithm_fails_signature(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    response["selected"] = "HQC-3"
    with pytest.raises(ValueError, match="signature"):
        alice.receive(response)
    assert alice.session is None


def test_signed_unacceptable_selection_fails_policy(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    response["selected"] = "HQC-3"
    resign(bob.identity, response)
    with pytest.raises(ValueError, match="Policy violation"):
        alice.receive(response)


def test_valid_signature_from_substituted_identity_rejected(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    public, secret = signature_keypair()
    offer["identity"] = b64(public)
    offer["signature"] = b64(
        sign(secret, canonical({k: v for k, v in offer.items() if k != "signature"}))
    )
    with pytest.raises(ValueError, match="pinned fingerprint"):
        bob.receive(offer)


def test_handshake_offer_and_response_replays_rejected(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    response = bob.receive(offer)
    with pytest.raises(ValueError, match="Replay rejected"):
        bob.receive(offer)
    finish = alice.receive(response)
    ack = bob.receive(finish)
    alice.receive(ack)
    with pytest.raises(ValueError, match="Replay rejected"):
        alice.receive(response)
    with pytest.raises(ValueError, match="Replay rejected"):
        bob.receive(finish)


def test_stale_signed_offer_rejected(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    offer["time"] = int(time.time()) - 120
    resign(alice.identity, offer)
    with pytest.raises(ValueError, match="stale handshake"):
        bob.receive(offer)


def test_signed_modified_kem_key_fails_size_validation(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    offer["kem_keys"]["ML-KEM-768"] = b64(b"bad")
    resign(alice.identity, offer)
    with pytest.raises(ValueError, match="public key.*length"):
        bob.receive(offer)


def test_signed_modified_ciphertext_fails_confirmation(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    data = bytearray(unb64(response["ciphertext"]))
    data[0] ^= 1
    response["ciphertext"] = b64(bytes(data))
    resign(bob.identity, response)
    with pytest.raises(ValueError, match="confirmation"):
        alice.receive(response)
    assert alice.session is None


def test_initiator_key_confirmation_required(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    finish = alice.receive(response)
    finish["confirmation"] = b64(b"wrong")
    with pytest.raises(ValueError, match="confirmation"):
        bob.receive(finish)
    assert bob.session is None


def test_transcript_offer_hash_bound(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    response["offer_hash"] = b64(bytes(32))
    resign(bob.identity, response)
    with pytest.raises(ValueError, match="transcript mismatch"):
        alice.receive(response)


def test_tamper_does_not_consume_receive_chain(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    original = alice.session.seal("Do not display corrupt plaintext")
    tampered = deepcopy(original)
    ct = bytearray(unb64(tampered["ciphertext"]))
    ct[-1] ^= 1
    tampered["ciphertext"] = b64(bytes(ct))
    chain = bob.session._receive_chain
    with pytest.raises(ValueError, match="integrity verification failed"):
        bob.session.open(tampered)
    assert bob.session.receive_count == 0 and bob.session._receive_chain == chain
    assert bob.session.open(original) == "Do not display corrupt plaintext"


def test_replay_and_reordered_message_rejection(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    first, second = alice.session.seal("first"), alice.session.seal("second")
    with pytest.raises(ValueError, match="Out-of-order"):
        bob.session.open(second)
    assert bob.session.receive_count == 0
    assert bob.session.open(first) == "first"
    with pytest.raises(ValueError, match="Replay rejected"):
        bob.session.open(first)
    assert bob.session.open(second) == "second"


def test_fresh_message_keys_and_nonce_counters(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    keys = []
    packets = []
    for _ in range(4):
        keys.append(hkdf(alice.session._send_chain, b"crytosage/1/message-key"))
        packets.append(alice.session.seal("same plaintext"))
    assert len(set(keys)) == 4
    assert [p["counter"] for p in packets] == [0, 1, 2, 3]
    assert len({p["ciphertext"] for p in packets}) == 4
    assert all(bob.session.open(p) == "same plaintext" for p in packets)


@pytest.mark.parametrize("counter", [True, -1, 1.0, "0", REKEY_AFTER])
def test_malformed_counter_rejected(peers, counter):
    alice, bob = peers
    complete_handshake(alice, bob)
    packet = alice.session.seal("text")
    packet["counter"] = counter
    with pytest.raises(ValueError, match="counter"):
        bob.session.open(packet)


@pytest.mark.parametrize(
    "field,value",
    [("sid", "0" * 64), ("from", "Mallory"), ("to", "Mallory"), ("v", "bad")],
)
def test_message_context_authenticated(peers, field, value):
    alice, bob = peers
    complete_handshake(alice, bob)
    packet = alice.session.seal("text")
    packet[field] = value
    with pytest.raises(ValueError):
        bob.session.open(packet)
    assert bob.session.receive_count == 0


def test_rekey_changes_session_and_old_ciphertext_rejected(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    old = alice.session.seal("old session")
    sid = alice.session.session_id
    complete_handshake(alice, bob)
    assert alice.session.session_id != sid
    with pytest.raises(ValueError, match="different session"):
        bob.session.open(old)
    assert bob.session.open(alice.session.seal("new session")) == "new session"


def test_ratchet_cap_requires_rekey(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    for _ in range(REKEY_AFTER):
        bob.session.open(alice.session.seal("message"))
    with pytest.raises(ValueError, match="Re-key required"):
        alice.session.seal("exceeds epoch")


def test_handshake_timeout_recovery(peers):
    alice, bob = peers
    alice.initiate("Bob")
    alice.pending["expires"] = time.monotonic() - 1
    assert alice.expire() and alice.pending is None
    complete_handshake(alice, bob)
    assert bob.session.open(alice.session.seal("recovered")) == "recovered"


@pytest.mark.parametrize(
    "packet", [None, {}, [], {"type": "unknown"}, {"type": "finish"}]
)
def test_malformed_protocol_rejects_without_session(peers, packet):
    alice, bob = peers
    with pytest.raises(ValueError):
        bob.receive(packet)
    assert bob.session is None


def test_public_session_does_not_export_secrets(peers):
    alice, bob = peers
    complete_handshake(alice, bob)
    public = alice.session.public()
    assert not any(
        k.startswith("_")
        or k
        in {
            "private_key",
            "secret",
            "root_key",
            "message_key",
            "send_chain",
            "receive_chain",
        }
        for k in public
    )
    assert alice.session._send_chain.hex() not in str(public)


def test_malformed_response_missing_sid_is_protocol_error(peers):
    alice, bob = peers
    response = bob.receive(alice.initiate("Bob"))
    del response["sid"]
    resign(bob.identity, response)
    with pytest.raises(ValueError):
        alice.receive(response)


def test_malformed_peer_name_is_protocol_error(peers):
    alice, bob = peers
    offer = alice.initiate("Bob")
    offer["from"] = ["Alice"]
    resign(alice.identity, offer)
    with pytest.raises(ValueError):
        bob.receive(offer)


def test_hqc_handshake_requires_explicit_policy_agility(peers):
    alice, bob = peers
    for peer in (alice, bob):
        peer.policy["allow_experimental"] = True
        peer.policy["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    complete_handshake(alice, bob)
    assert alice.session.algorithm == bob.session.algorithm == "HQC-3"
    assert "experimental" in alice.session.reason
    assert (
        bob.session.open(alice.session.seal("Real HQC level-3 session"))
        == "Real HQC level-3 session"
    )


def test_contact_trust_pin_persists_on_restart(peers):
    alice, bob = peers
    restarted = Identity(alice.identity.directory, "Alice")
    restarted.check_peer("Bob", bob.identity.public)
    assert restarted.trusted["Bob"] == bob.identity.fingerprint


def test_changed_nonce_and_id_are_signed(peers):
    alice, bob = peers
    original = alice.initiate("Bob")
    for field in ("nonce", "sid"):
        altered = deepcopy(original)
        altered[field] = "0" * 64
        with pytest.raises(ValueError, match="signature"):
            bob.receive(altered)


def test_duplicate_response_before_ack_is_replay_not_internal_error():
    from attacks.simulator import make_pair

    with make_pair() as (alice, bob):
        response = bob.receive(alice.initiate("Bob"))
        finish = alice.receive(response)
        with pytest.raises(ValueError, match="Replay rejected"):
            alice.receive(response)
        ack = bob.receive(finish)
        alice.receive(ack)
        assert alice.session and bob.session
