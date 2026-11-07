"""V2 isolated lab outcomes are derived from real implementations, never fixtures."""

import json
import pytest
from attacks.simulator import ALL_SCENARIOS, CATALOG, SCENARIOS, run_scenario


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_v2_catalog_exercises_real_rejection_or_secure_abort(scenario):
    result = run_scenario(scenario)
    assert result["attempted"], result
    assert result["status"] == "blocked", result
    assert result["blocked"], result
    assert result["reason"]
    assert result["elapsed_ms"] > 0
    assert result["timeline"][0]["phase"] == "launched"
    assert result["timeline"][-1]["phase"] == "protected"
    times = [event["elapsed_ms"] for event in result["timeline"]]
    assert times == sorted(times)
    assert {
        "name",
        "objective",
        "mutation",
        "security_reason",
        "protocol_response",
        "scope",
    } <= result.keys()


def test_v2_catalog_is_unique_and_legacy_interface_stays_compatible():
    assert len(CATALOG) == len(ALL_SCENARIOS) == 12
    assert len(set(ALL_SCENARIOS)) == 12
    assert SCENARIOS == ("downgrade", "identity", "replay", "tamper", "invalid")
    assert all(set(row) == {"id", "name", "objective", "mutation"} for row in CATALOG)


def test_v2_lab_setup_error_is_not_a_security_success(monkeypatch):
    import attacks.simulator as lab

    def broken_setup():
        raise RuntimeError("arbitrary sensitive setup detail must not be exported")

    monkeypatch.setattr(lab, "make_pair", broken_setup)
    result = lab.run_scenario("tamper")
    assert result["status"] == "infrastructure_error"
    assert not result["blocked"] and not result["attempted"]
    assert "sensitive" not in json.dumps(result)


def test_v2_lab_unexpected_validation_error_is_inconclusive(monkeypatch):
    import attacks.simulator as lab

    def prepare(*args):
        def reject():
            raise ValueError("Unexpected local validation error")

        return reject

    monkeypatch.setattr(lab, "_prepare", prepare)
    result = lab.run_scenario("tamper")
    assert result["status"] == "inconclusive"
    assert result["attempted"] and not result["blocked"]


def test_v2_lab_acceptance_is_reported_as_failure(monkeypatch):
    import attacks.simulator as lab

    monkeypatch.setattr(lab, "_prepare", lambda *args: lambda: None)
    result = lab.run_scenario("tamper")
    assert result["status"] == "accepted"
    assert result["attempted"] and not result["blocked"]
    assert result["timeline"][-1]["phase"] == "accepted"


def test_v2_lab_exception_during_attack_is_infrastructure_failure(monkeypatch):
    import attacks.simulator as lab

    def prepare(*args):
        def crash():
            raise OSError("do not export arbitrary filesystem paths")

        return crash

    monkeypatch.setattr(lab, "_prepare", prepare)
    result = lab.run_scenario("tamper")
    assert result["status"] == "infrastructure_error"
    assert result["attempted"] and not result["blocked"]
    assert "filesystem" not in json.dumps(result)


def test_v2_results_do_not_include_packets_or_secret_material():
    result = run_scenario("identity")
    assert result["blocked"]
    forbidden = {
        "public",
        "secret",
        "private_key",
        "shared",
        "shared_secret",
        "_secret",
        "packet",
        "ciphertext",
        "signature",
    }

    def check(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for item in value.values():
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)

    check(result)


def test_v2_repeated_runs_create_independent_experiments():
    first, second = run_scenario("handshake_replay"), run_scenario("handshake_replay")
    assert first["blocked"] and second["blocked"]
    assert first["timeline"] is not second["timeline"]
    assert first["timeline"][0]["time"] != second["timeline"][0]["time"]


def test_v2_unsupported_algorithm_tests_actual_whitelist():
    result = run_scenario("unsupported")
    assert result["blocked"]
    assert "unsupported" in result["reason"].lower()
    assert "signature" not in result["reason"].lower()


def test_v2_unknown_scenario_is_not_a_test_success():
    with pytest.raises(ValueError, match="Unsupported"):
        run_scenario("not-a-real-experiment")
