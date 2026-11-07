"""Decision explanations and guarded policy edits exercise the real selector."""

from copy import deepcopy
import json
import os

import pytest

from crypto.primitives import available_algorithms
from policy.engine import PolicyError, load_policy, select, validate_policy
from policy.manager import safe_defaults, save_policy, validate_update


def offer(policy=None):
    return {
        "algorithms": [a["name"] for a in available_algorithms()],
        "policy": deepcopy(policy or safe_defaults()),
    }


def test_decision_reports_actual_eligible_and_restricted_candidates():
    decision = select(offer(), offer())
    trace = decision["decision"]
    candidates = {row["name"]: row for row in trace["candidates"]}
    assert candidates["ML-KEM-768"]["eligible"]
    assert not candidates["HQC-3"]["eligible"]
    assert any(
        check["stage"] == "experimental" and not check["passed"]
        for check in candidates["HQC-3"]["checks"]
    )
    assert trace["selected"] == "ML-KEM-768"
    assert [step["stage"] for step in trace["steps"]] == [
        "candidates",
        "policy",
        "compatibility",
        "security_level",
        "performance",
        "selection",
    ]
    assert not trace["performance"]["used_for_tiebreak"]
    assert "only one eligible" in trace["performance"]["detail"]


def test_rejection_retains_explanation_and_never_relaxes_policy():
    a, b = offer(), offer()
    a["policy"]["minimum_security_level"] = 5
    with pytest.raises(PolicyError) as rejection:
        select(a, b)
    trace = rejection.value.decision
    assert trace["selected"] is None
    assert all(not candidate["eligible"] for candidate in trace["candidates"])
    assert trace["steps"][-1]["stage"] == "selection"
    assert "refused" in trace["steps"][-1]["detail"]
    assert a["policy"]["minimum_security_level"] == 5


def test_missing_peer_capability_is_visible_not_silently_omitted():
    a, b = offer(), offer()
    b["algorithms"] = ["HQC-3"]
    b["policy"]["allow_experimental"] = True
    with pytest.raises(PolicyError) as rejection:
        select(a, b)
    ml = next(
        row
        for row in rejection.value.decision["candidates"]
        if row["name"] == "ML-KEM-768"
    )
    assert not next(
        check for check in ml["checks"] if check["stage"] == "compatibility"
    )["passed"]


def test_malformed_policy_rejection_exposes_validation_trace():
    a, b = offer(), offer()
    a["policy"]["allow_experimental"] = "yes"
    with pytest.raises(PolicyError) as rejection:
        select(a, b)
    assert rejection.value.decision["selected"] is None
    assert rejection.value.decision["steps"][0]["stage"] == "validation"


def test_interval_is_stricter_signed_offer_value_and_trace_symmetric():
    a, b = offer(), offer()
    a["policy"]["rekey_interval"] = 20
    b["policy"]["rekey_interval"] = 75
    before_a, before_b = deepcopy(a), deepcopy(b)
    result = select(a, b)
    assert result["rekey_interval"] == 20
    assert result["decision"]["rekey_interval"] == 20
    assert result == select(b, a)
    assert a == before_a and b == before_b


def test_missing_interval_preserves_v1_100_message_bound():
    a, b = offer(), offer()
    a["policy"].pop("rekey_interval")
    b["policy"].pop("rekey_interval")
    assert select(a, b)["rekey_interval"] == 100


@pytest.mark.parametrize("interval", [0, 101, True, 3.5, "30", None])
def test_invalid_intervals_fail_securely(interval):
    policy = safe_defaults()
    policy["rekey_interval"] = interval
    with pytest.raises(PolicyError, match="Re-key interval"):
        validate_policy(policy)


def test_measured_tie_break_is_explained_only_when_gates_tie():
    a, b = offer(), offer()
    for side in (a, b):
        side["policy"]["allow_experimental"] = True
        for rule in side["policy"]["algorithms"].values():
            rule.update(status="experimental", priority=1)
        side["measurements"] = {
            "ML-KEM-768": {"handshake_ms": 10},
            "HQC-3": {"handshake_ms": 1},
        }
    result = select(a, b)
    assert result["algorithm"] == "HQC-3"
    assert result["decision"]["performance"]["used_for_tiebreak"]
    assert result == select(b, a)


def test_performance_does_not_claim_to_override_recommended_status():
    a, b = offer(), offer()
    for side in (a, b):
        side["policy"]["allow_experimental"] = True
        side["measurements"] = {
            "ML-KEM-768": {"handshake_ms": 100},
            "HQC-3": {"handshake_ms": 0},
        }
    result = select(a, b)
    assert result["algorithm"] == "ML-KEM-768"
    assert not result["decision"]["performance"]["used_for_tiebreak"]
    assert "policy status/priority" in result["decision"]["performance"]["detail"]


def test_safe_defaults_are_independent_copies_of_safe_baseline():
    changed = safe_defaults()
    changed["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    assert safe_defaults()["algorithms"]["ML-KEM-768"]["status"] == "recommended"
    assert not safe_defaults()["allow_experimental"]


@pytest.mark.parametrize(
    "change",
    [
        {"allow_experimental": True},
        {"rekey_interval": 100},
        {"minimum_security_level": 3},
    ],
)
def test_policy_relaxations_require_explicit_confirmation(change):
    current = safe_defaults()
    current.update(rekey_interval=20, minimum_security_level=4)
    changed = deepcopy(current)
    changed.update(change)
    with pytest.raises(PolicyError, match="Explicit restriction confirmation"):
        validate_update(changed, current)
    assert validate_update(changed, current, True) == changed


def test_allowing_previously_prohibited_algorithm_requires_confirmation():
    current = safe_defaults()
    current["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    with pytest.raises(PolicyError, match="Explicit restriction confirmation"):
        validate_update(safe_defaults(), current)
    assert (
        validate_update(safe_defaults(), current, True)["algorithms"]["ML-KEM-768"][
            "status"
        ]
        == "recommended"
    )


def test_security_floor_cannot_be_bypassed_with_confirmation():
    policy = safe_defaults()
    policy["minimum_security_level"] = 2
    with pytest.raises(PolicyError, match="minimum security level 3"):
        validate_update(policy, safe_defaults(), True)


def test_more_restrictive_change_does_not_require_confirmation():
    current = safe_defaults()
    changed = deepcopy(current)
    changed.update(rekey_interval=10, minimum_security_level=5)
    changed["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
    assert validate_update(changed, current) == changed


@pytest.mark.parametrize(
    "extra", [{"ignored_security_option": True}, {"allow_experimentals": True}]
)
def test_unknown_controls_are_not_silently_ignored(extra):
    policy = safe_defaults()
    policy.update(extra)
    with pytest.raises(PolicyError, match="Unknown policy control"):
        validate_update(policy, safe_defaults())


def test_save_is_atomic_private_and_does_not_mutate_inputs(tmp_path):
    current = safe_defaults()
    changed = deepcopy(current)
    changed["rekey_interval"] = 25
    before = deepcopy(changed)
    path = tmp_path / "policy.json"
    saved = save_policy(path, changed, current)
    assert saved == json.loads(path.read_text()) == before
    assert changed == before and current == safe_defaults()
    assert os.stat(path).st_mode & 0o077 == 0
    assert not list(tmp_path.glob("*.tmp"))
    assert load_policy(path) == saved


def test_failed_validation_preserves_existing_policy_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(safe_defaults()))
    before = path.read_bytes()
    invalid = safe_defaults()
    invalid["allow_experimental"] = True
    with pytest.raises(PolicyError):
        save_policy(path, invalid, safe_defaults())
    assert path.read_bytes() == before
