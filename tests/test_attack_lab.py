import pytest
from attacks.simulator import SCENARIOS, run_scenario


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_controlled_attack_is_really_rejected(scenario):
    result = run_scenario(scenario)
    assert result["attempted"] and result["blocked"], result
    assert result["elapsed_ms"] > 0
    assert result["reason"] and "accepted" not in result["reason"]
    expected = {
        "downgrade": "signature",
        "identity": "fingerprint",
        "replay": "Replay",
        "tamper": "integrity",
        "invalid": "length",
    }
    assert expected[scenario] in result["reason"]


def test_unknown_lab_scenario_is_not_success():
    with pytest.raises(ValueError):
        run_scenario("invented")


def test_mutation_preserves_original_and_replay_packet():
    from attacks.simulator import mutate_packet

    original = {"type": "response", "selected": "ML-KEM-768"}
    mutated = mutate_packet("downgrade", original)
    assert original["selected"] == "ML-KEM-768" and mutated["selected"] == "HQC-3"
    replay = mutate_packet("replay", original)
    assert replay == original and replay is not original


def test_relay_mutations_have_no_crypto_or_client_imports():
    import ast
    from pathlib import Path

    source = Path("attacks/mutations.py").read_text()
    modules = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add((node.module or "").split(".")[0])
    assert modules <= {"__future__", "base64", "copy", "os"}
    assert not modules & {"crypto", "protocol", "client", "oqs", "cryptography"}


def test_relay_identity_mutation_changes_only_public_identity(peers):
    from attacks.mutations import mutate_packet
    from protocol.identity import unb64

    alice, bob = peers
    packet = alice.initiate("Bob")
    mutated = mutate_packet("identity", packet)
    assert len(unb64(mutated["identity"])) == len(alice.identity.public)
    assert mutated["signature"] == packet["signature"]
    assert mutated["identity"] != packet["identity"]
    with pytest.raises(ValueError, match="fingerprint"):
        bob.receive(mutated)
