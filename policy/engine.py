"""Authenticate these offers in the protocol before accepting selection results."""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from crypto.primitives import available_algorithms


class PolicyError(ValueError):
    """No valid, mutually acceptable secure algorithm can be selected."""


KNOWN = {"ML-KEM-768": 3, "HQC-3": 3}
PREFERENCES = {
    "latency": ("handshake_ms",),
    "cpu": ("cpu_ms",),
    "memory": ("peak_rss_bytes",),
    "bandwidth": ("handshake_bytes",),
    "balanced": ("handshake_ms", "cpu_ms", "peak_rss_bytes", "handshake_bytes"),
}


def _measurement(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value <= 1e18 and math.isfinite(value)


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise PolicyError("Policy must be an object")
    level = policy.get("minimum_security_level")
    if type(level) is not int or level not in range(1, 6):
        raise PolicyError("Minimum security level must be an integer from 1 to 5")
    if type(policy.get("allow_experimental")) is not bool:
        raise PolicyError("allow_experimental must be a boolean")
    if policy.get("performance_preference") not in PREFERENCES:
        raise PolicyError("Unsupported performance preference")
    rules = policy.get("algorithms")
    if not isinstance(rules, dict) or not rules or len(rules) > 16:
        raise PolicyError("Policy must contain algorithm rules")
    for name, rule in rules.items():
        if name not in KNOWN or not isinstance(rule, dict):
            raise PolicyError("Unsupported policy algorithm")
        if rule.get("status") not in {"recommended", "experimental", "prohibited"}:
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
    if (not isinstance(names, list) or len(names) > 16
            or any(not isinstance(name, str) or name not in KNOWN for name in names)
            or len(set(names)) != len(names)):
        raise PolicyError("Malformed or unsupported algorithm offer")
    return set(names), validate_policy(offer.get("policy"))


def select(local_offer: dict[str, Any], peer_offer: dict[str, Any],
           measurements: dict[str, Any] | None = None) -> dict[str, Any]:
    """Choose symmetrically; performance can never override policy admissibility.

    Untrusted peers cannot assert availability: only this process's actual library
    capabilities and the two signed policies decide eligibility. Measurements are
    local observations, never values accepted from relay traffic. The protocol binds both measured
    profiles into its signed transcript. Each usable metric is the mean of both
    snapshots; a metric missing from either snapshot cannot influence selection.
    """
    left_names, left = _offer(local_offer)
    right_names, right = _offer(peer_offer)
    installed = {row["name"]: row for row in available_algorithms()
                 if row.get("available", True)}
    minimum = max(left["minimum_security_level"], right["minimum_security_level"])
    candidates: list[tuple[str, int, int]] = []
    excluded: list[str] = []
    for name in sorted(left_names & right_names):
        row = installed.get(name)
        rules = [side["algorithms"].get(name) for side in (left, right)]
        if row is None or KNOWN[name] < minimum:
            excluded.append(f"{name}: implementation unavailable or security level below {minimum}")
            continue
        if any(rule is None or rule["status"] == "prohibited" for rule in rules):
            excluded.append(f"{name}: denied by a local policy")
            continue
        experimental = any(rule["status"] == "experimental" for rule in rules)
        experimental |= row.get("status") == "experimental"
        if experimental and not (left["allow_experimental"] and right["allow_experimental"]):
            excluded.append(f"{name}: experimental implementation requires both policies to opt in")
            continue
        candidates.append((name, int(experimental), sum(rule["priority"] for rule in rules)))
    if not candidates:
        suffix = "; ".join(excluded) or "no common offered algorithms"
        raise PolicyError(f"No mutually acceptable secure algorithm: {suffix}")
    if measurements is None:
        snapshots = [offer.get("measurements", {}) for offer in (local_offer, peer_offer)]
        measurements = {}
        for name, _, _ in candidates:
            combined = {}
            for metric in sorted({metric for values in PREFERENCES.values() for metric in values}):
                values = [snapshot.get(name, {}).get(metric) if isinstance(snapshot, dict)
                          and isinstance(snapshot.get(name), dict) else None for snapshot in snapshots]
                if all(_measurement(value) for value in values):
                    combined[metric] = sum(values) / len(values)
            measurements[name] = combined
    data = (measurements or {}).get("selection_measurements", measurements or {})
    if not isinstance(data, dict):
        raise PolicyError("Measured performance profile must be an object")
    metrics = sorted(set(PREFERENCES[left["performance_preference"]]
                         + PREFERENCES[right["performance_preference"]]))
    usable: dict[str, dict[str, float]] = {}
    for metric in metrics:
        values = {name: data.get(name, {}).get(metric) if isinstance(data.get(name), dict) else None
                  for name, _, _ in candidates}
        if all(_measurement(value) for value in values.values()):
            usable[metric] = values
    def score(name: str) -> float:
        return sum(values[name] / max(max(values.values()), 1e-12) for values in usable.values())
    chosen, experimental, priority = min(candidates, key=lambda item: (item[1], item[2], score(item[0]), item[0]))
    measured = ", ".join(usable) if usable else "no complete comparable measured profile; deterministic name tie-break"
    reason = (f"{chosen}: both clients permit security level {KNOWN[chosen]} (minimum {minimum}); "
              f"{'experimental, explicitly allowed by both' if experimental else 'recommended'}; "
              f"combined policy priority {priority}; performance: {measured}.")
    return {"algorithm": chosen, "security_level": KNOWN[chosen], "reason": reason}
