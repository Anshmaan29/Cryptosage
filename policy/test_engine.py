"""Policy regression checks against actual installed liboqs capabilities."""

import pytest
from crypto.primitives import available_algorithms
from policy.engine import PolicyError, load_policy, select


def offer():
    return {
        "algorithms": [item["name"] for item in available_algorithms()],
        "policy": load_policy(),
    }


def test_default_selects_recommended_real_implementation():
    value = offer()
    assert select(value, value)["algorithm"] == "ML-KEM-768"


def test_prohibition_from_either_endpoint_is_authoritative():
    left, right = offer(), offer()
    right["policy"]["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    with pytest.raises(PolicyError, match="No mutually acceptable"):
        select(left, right)


def test_minimum_security_cannot_be_reduced_for_performance():
    left, right = offer(), offer()
    right["policy"]["minimum_security_level"] = 5
    with pytest.raises(PolicyError):
        select(left, right, {"ML-KEM-768": {"handshake_ms": 0}})


def test_experimental_requires_both_opt_ins():
    left, right = offer(), offer()
    for value in (left, right):
        value["algorithms"] = ["HQC-3"]
    left["policy"]["allow_experimental"] = True
    with pytest.raises(PolicyError):
        select(left, right)
    right["policy"]["allow_experimental"] = True
    assert select(left, right)["algorithm"] == "HQC-3"


def test_symmetric_signed_measurement_selection():
    left, right = offer(), offer()
    for value in (left, right):
        value["policy"]["allow_experimental"] = True
        for rule in value["policy"]["algorithms"].values():
            rule.update(status="experimental", priority=1)
    left["measurements"] = {
        "ML-KEM-768": {"handshake_ms": 10},
        "HQC-3": {"handshake_ms": 1},
    }
    right["measurements"] = {
        "ML-KEM-768": {"handshake_ms": 12},
        "HQC-3": {"handshake_ms": 2},
    }
    assert select(left, right) == select(right, left)
    assert select(left, right)["algorithm"] == "HQC-3"


def test_security_preference_precedes_performance():
    left, right = offer(), offer()
    for value in (left, right):
        value["policy"]["allow_experimental"] = True
        value["measurements"] = {
            "ML-KEM-768": {"handshake_ms": 1000},
            "HQC-3": {"handshake_ms": 0},
        }
    assert select(left, right)["algorithm"] == "ML-KEM-768"


@pytest.mark.parametrize(
    "names", [["unknown"], ["ML-KEM-768", "ML-KEM-768"], "ML-KEM-768", [None]]
)
def test_reject_malformed_offers(names):
    left, right = offer(), offer()
    left["algorithms"] = names
    with pytest.raises(PolicyError):
        select(left, right)


@pytest.mark.parametrize("minimum", [True, 0, 6, "3"])
def test_reject_invalid_security_levels(minimum):
    left, right = offer(), offer()
    left["policy"]["minimum_security_level"] = minimum
    with pytest.raises(PolicyError):
        select(left, right)


def test_nonfinite_and_enormous_measurements_cannot_crash_selection():
    left, right = offer(), offer()
    left["measurements"] = {"ML-KEM-768": {"handshake_ms": 10**10000}}
    right["measurements"] = {"ML-KEM-768": {"handshake_ms": float("nan")}}
    assert select(left, right)["algorithm"] == "ML-KEM-768"
