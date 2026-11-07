from copy import deepcopy
import pytest
from crypto.primitives import available_algorithms
from policy.engine import load_policy, select, PolicyError


def offer(policy=None, names=None):
    return {
        "algorithms": names
        if names is not None
        else [a["name"] for a in available_algorithms()],
        "policy": deepcopy(policy or load_policy()),
    }


def test_default_prefers_recommended_ml_kem():
    assert select(offer(), offer())["algorithm"] == "ML-KEM-768"


def test_prohibited_algorithm_never_selected_even_if_faster():
    left = offer()
    left["policy"]["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    with pytest.raises(PolicyError, match="No mutually acceptable"):
        select(left, offer(), {"ML-KEM-768": {"handshake_ms": 0}})


def test_no_common_algorithms_fails():
    with pytest.raises(PolicyError, match="No mutually acceptable"):
        select(offer(names=["ML-KEM-768"]), offer(names=["HQC-3"]))


def test_experimental_requires_both_clients_opt_in():
    left = offer(names=["HQC-3"])
    right = offer(names=["HQC-3"])
    left["policy"]["allow_experimental"] = True
    with pytest.raises(PolicyError, match="both policies"):
        select(left, right)
    right["policy"]["allow_experimental"] = True
    assert select(left, right)["algorithm"] == "HQC-3"


def test_security_minimum_overrides_performance():
    policy = load_policy()
    policy["minimum_security_level"] = 5
    with pytest.raises(PolicyError, match="security level below 5"):
        select(offer(policy), offer(), {"ML-KEM-768": {"handshake_ms": 0}})


@pytest.mark.parametrize(
    "names", [["X25519"], ["ML-KEM-768", "ML-KEM-768"], [None], "ML-KEM-768"]
)
def test_invalid_algorithm_offers_rejected(names):
    with pytest.raises(PolicyError):
        select(offer(names=names), offer())


def test_policy_order_is_symmetric():
    left = offer()
    right = offer()
    left["measurements"] = {"ML-KEM-768": {"handshake_ms": 1}}
    right["measurements"] = {"ML-KEM-768": {"handshake_ms": 2}}
    assert select(left, right) == select(right, left)
