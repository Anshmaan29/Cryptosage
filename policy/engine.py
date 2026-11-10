"""Authenticate these offers in the protocol before accepting selection results."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, TypeGuard

from crypto.primitives import available_algorithms


class PolicyError(ValueError):
    """No valid, mutually acceptable secure algorithm can be selected."""

    def __init__(self, message: str, decision: dict[str, Any] | None = None):
        super().__init__(message)
        self.decision = decision or {
            "candidates": [],
            "steps": [{"stage": "validation", "detail": message}],
            "performance": {},
            "selected": None,
        }


KNOWN = {"ML-KEM-768": 3, "HQC-3": 3}
PREFERENCES = {
    "latency": ("handshake_ms",),
    "cpu": ("cpu_ms",),
    "memory": ("peak_rss_bytes",),
    "bandwidth": ("handshake_bytes",),
    "balanced": ("handshake_ms", "cpu_ms", "peak_rss_bytes", "handshake_bytes"),
}


def _measurement(value: Any) -> TypeGuard[float]:
    return type(value) in (int, float) and 0 <= value <= 1e18 and math.isfinite(value)


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise PolicyError("Policy must be an object")
    level = policy.get("minimum_security_level")
    if type(level) is not int or level not in range(1, 6):
        raise PolicyError("Minimum security level must be an integer from 1 to 5")
    if type(policy.get("allow_experimental")) is not bool:
        raise PolicyError("allow_experimental must be a boolean")
    if (
        not isinstance(policy.get("performance_preference"), str)
        or policy["performance_preference"] not in PREFERENCES
    ):
        raise PolicyError("Unsupported performance preference")
    interval = policy.get("rekey_interval", 100)
    if type(interval) is not int or not 1 <= interval <= 100:
        raise PolicyError("Re-key interval must be an integer from 1 to 100 messages")
    rules = policy.get("algorithms")
    if not isinstance(rules, dict) or not rules or len(rules) > 16:
        raise PolicyError("Policy must contain algorithm rules")
    for name, rule in rules.items():
        if name not in KNOWN or not isinstance(rule, dict):
            raise PolicyError("Unsupported policy algorithm")
        if rule.get("status") not in ("recommended", "experimental", "prohibited"):
            raise PolicyError("Invalid algorithm status")
        priority = rule.get("priority")
        if type(priority) is not int or not 0 <= priority <= 1000:
            raise PolicyError("Algorithm priority must be an integer from 0 to 1000")
    return policy


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path is not None else Path(__file__).with_name("policy.json")
    return validate_policy(json.loads(target.read_text(encoding="utf-8")))


def _offer(offer: dict[str, Any]) -> tuple[set[str], dict[str, Any]]:
    if not isinstance(offer, dict):
        raise PolicyError("Offer must be an object")
    names = offer.get("algorithms")
    if (
        not isinstance(names, list)
        or len(names) > 16
        or any(not isinstance(name, str) or name not in KNOWN for name in names)
        or len(set(names)) != len(names)
    ):
        raise PolicyError("Malformed or unsupported algorithm offer")
    return set(names), validate_policy(offer.get("policy"))


def admissible_algorithms(policy: dict) -> list[str]:
    rules = policy["algorithms"]
    return [
        row["name"]
        for row in available_algorithms()
        if (rule := rules.get(row["name"])) is not None
        and rule["status"] != "prohibited"
        and row["security_level"] >= policy["minimum_security_level"]
        and (
            policy["allow_experimental"]
            or "experimental" not in (rule["status"], row["status"])
        )
    ]


def select(
    local_offer: dict[str, Any],
    peer_offer: dict[str, Any],
    measurements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Choose symmetrically; performance can never override policy admissibility.

    Untrusted peers cannot assert availability: only this process's actual library
    capabilities and the two signed policies decide eligibility. Measurements are
    local observations, never values accepted from relay traffic. The protocol binds both measured
    profiles into its signed transcript. Each usable metric is the mean of both
    snapshots; a metric missing from either snapshot cannot influence selection.
    """
    left_names, left = _offer(local_offer)
    right_names, right = _offer(peer_offer)
    installed = {
        row["name"]: row for row in available_algorithms() if row.get("available", True)
    }
    minimum = max(left["minimum_security_level"], right["minimum_security_level"])
    interval = min(left.get("rekey_interval", 100), right.get("rekey_interval", 100))
    candidates: list[tuple[str, int, int]] = []
    rows = []
    excluded = []
    for name in sorted(KNOWN):
        row = installed.get(name)
        rules = [side["algorithms"].get(name) for side in (left, right)]
        permitted = all(
            rule is not None and rule["status"] != "prohibited" for rule in rules
        )
        compatible = name in left_names and name in right_names and row is not None
        actual_level = row.get("security_level", 0) if row else 0
        level = min(actual_level, KNOWN[name]) if type(actual_level) is int else 0
        sufficient = level >= minimum
        experimental = any(rule and rule["status"] == "experimental" for rule in rules)
        experimental |= bool(row and row.get("status") == "experimental")
        opted_in = not experimental or (
            left["allow_experimental"] and right["allow_experimental"]
        )
        checks = [
            {
                "stage": "policy",
                "passed": permitted,
                "detail": "Both policies permit this algorithm"
                if permitted
                else "Denied by a local policy or missing policy rule",
            },
            {
                "stage": "compatibility",
                "passed": compatible,
                "detail": "Offered by both clients and enabled in the local library"
                if compatible
                else "Not offered by both clients or implementation unavailable",
            },
            {
                "stage": "security_level",
                "passed": sufficient,
                "detail": f"Security level {level} meets minimum {minimum}"
                if sufficient
                else f"Implementation unavailable or security level below {minimum}",
            },
            {
                "stage": "experimental",
                "passed": bool(opted_in),
                "detail": "Experimental implementation explicitly allowed by both policies"
                if experimental and opted_in
                else "Experimental implementation requires both policies to opt in"
                if experimental
                else "Recommended implementation; no experimental opt-in required",
            },
        ]
        eligible = all(check["passed"] for check in checks)
        candidate = {
            "name": name,
            "eligible": eligible,
            "checks": checks,
            "security_level": level,
            "implementation_status": row.get("status") if row else "unavailable",
            "policy_statuses": sorted(
                rule["status"] if rule else "missing" for rule in rules
            ),
        }
        if eligible:
            priority = sum(rule["priority"] for rule in rules)
            candidate.update(priority=priority, experimental=bool(experimental))
            candidates.append((name, int(experimental), priority))
        else:
            excluded.append(
                name
                + ": "
                + "; ".join(check["detail"] for check in checks if not check["passed"])
            )
        rows.append(candidate)
    steps = [
        {
            "stage": "candidates",
            "detail": "Known candidates: " + ", ".join(sorted(KNOWN)),
        },
        {
            "stage": "policy",
            "detail": "Both signed policies validated; prohibited or missing rules are excluded",
        },
        {
            "stage": "compatibility",
            "detail": "Intersect both advertised capabilities with the installed implementation",
        },
        {
            "stage": "security_level",
            "detail": f"Require NIST security level {minimum}; security gates precede performance",
        },
    ]
    decision = {
        "candidates": rows,
        "steps": steps,
        "performance": {},
        "selected": None,
        "minimum_security_level": minimum,
        "rekey_interval": interval,
    }
    if not candidates:
        message = "No mutually acceptable secure algorithm: " + (
            "; ".join(excluded) or "no common offered algorithms"
        )
        steps.extend(
            [
                {
                    "stage": "performance",
                    "detail": "Not evaluated: no eligible candidates",
                },
                {
                    "stage": "selection",
                    "detail": "Session refused; no security rule was relaxed",
                },
            ]
        )
        raise PolicyError(message, decision)
    if measurements is None:
        snapshots = [
            offer.get("measurements", {}) for offer in (local_offer, peer_offer)
        ]
        measurements = {}
        for name, _, _ in candidates:
            combined = {}
            for metric in sorted(
                {metric for values in PREFERENCES.values() for metric in values}
            ):
                values = [
                    snapshot.get(name, {}).get(metric)
                    if isinstance(snapshot, dict)
                    and isinstance(snapshot.get(name), dict)
                    else None
                    for snapshot in snapshots
                ]
                valid = [value for value in values if _measurement(value)]
                if len(valid) == len(values):
                    combined[metric] = sum(valid) / len(valid)
            measurements[name] = combined
    if not isinstance(measurements, dict):
        raise PolicyError("Measured performance profile must be an object", decision)
    data = measurements.get("selection_measurements", measurements)
    if not isinstance(data, dict):
        raise PolicyError("Measured performance profile must be an object", decision)
    metrics = sorted(
        set(
            PREFERENCES[left["performance_preference"]]
            + PREFERENCES[right["performance_preference"]]
        )
    )
    usable: dict[str, dict[str, float]] = {}
    for metric in metrics:
        by_algorithm = {
            name: data.get(name, {}).get(metric)
            if isinstance(data.get(name), dict)
            else None
            for name, _, _ in candidates
        }
        comparable = {
            name: value for name, value in by_algorithm.items() if _measurement(value)
        }
        if len(comparable) == len(by_algorithm):
            usable[metric] = comparable

    def score(name: str) -> float:
        return sum(
            values[name] / max(max(values.values()), 1e-12)
            for values in usable.values()
        )

    chosen, chosen_experimental, priority = min(
        candidates, key=lambda item: (item[1], item[2], score(item[0]), item[0])
    )
    same_rank = [
        name
        for name, exp, prio in candidates
        if exp == chosen_experimental and prio == priority
    ]
    performance_used = bool(usable) and len(same_rank) > 1
    if performance_used:
        measured = (
            "comparable measured "
            + ", ".join(usable)
            + " used among equal policy ranks"
        )
    elif len(candidates) == 1:
        measured = "not used: only one eligible candidate"
    elif usable:
        measured = "available but policy status/priority determined selection before performance"
    else:
        measured = "no complete comparable measured profile; deterministic name tie-break within equal policy ranks"
    reason = (
        f"{chosen}: both clients permit security level {KNOWN[chosen]} (minimum {minimum}); "
        f"{'experimental, explicitly allowed by both' if chosen_experimental else 'recommended'}; "
        f"combined policy priority {priority}; performance: {measured}."
    )
    decision["performance"] = {
        "metrics": list(usable),
        "values": usable,
        "scores": {name: score(name) for name, _, _ in candidates},
        "used_for_tiebreak": performance_used,
        "detail": measured,
    }
    decision["selected"] = chosen
    steps.extend(
        [
            {"stage": "performance", "detail": measured},
            {"stage": "selection", "detail": reason},
        ]
    )
    return {
        "algorithm": chosen,
        "security_level": KNOWN[chosen],
        "reason": reason,
        "rekey_interval": interval,
        "decision": decision,
    }
