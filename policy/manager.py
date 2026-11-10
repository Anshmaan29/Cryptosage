"""Validated per-client policy editing; active sessions retain their signed policy."""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from policy.engine import PolicyError, validate_policy


def safe_defaults() -> dict[str, Any]:
    """Fresh safe baseline, independent of editable policy files."""
    return {
        "minimum_security_level": 3,
        "allow_experimental": False,
        "performance_preference": "latency",
        "rekey_interval": 100,
        "algorithms": {
            "ML-KEM-512": {"status": "prohibited", "priority": 1},
            "ML-KEM-768": {"status": "recommended", "priority": 1},
            "ML-KEM-1024": {"status": "recommended", "priority": 1},
            "HQC-1": {"status": "prohibited", "priority": 2},
            "HQC-3": {"status": "experimental", "priority": 2},
            "HQC-5": {"status": "experimental", "priority": 2},
        },
    }


def validate_update(
    policy: dict[str, Any], current: dict[str, Any], confirm_restrictions: bool = False
) -> dict[str, Any]:
    """Reject unknown controls and require a deliberate opt-in for relaxations."""
    validate_policy(policy)
    validate_policy(current)
    if type(confirm_restrictions) is not bool:
        raise PolicyError("Restriction confirmation must be a boolean")
    if set(policy) - set(safe_defaults()):
        raise PolicyError("Unknown policy control")
    for rule in policy["algorithms"].values():
        if set(rule) != {"status", "priority"}:
            raise PolicyError("Algorithm rules require only status and priority")
    if policy["minimum_security_level"] < 3:
        raise PolicyError(
            "Research policy manager requires minimum security level 3 or higher"
        )
    rank = {"prohibited": 0, "experimental": 1, "recommended": 2}
    relaxed = (
        policy["minimum_security_level"] < current["minimum_security_level"]
        or (policy["allow_experimental"] and not current["allow_experimental"])
        or policy.get("rekey_interval", 100) > current.get("rekey_interval", 100)
    )
    for name, rule in policy["algorithms"].items():
        prior = current["algorithms"].get(name, {"status": "prohibited"})
        relaxed |= rank[rule["status"]] > rank[prior["status"]]
    if relaxed and not confirm_restrictions:
        raise PolicyError(
            "Explicit restriction confirmation is required for a less restrictive policy"
        )
    result = deepcopy(policy)
    result.setdefault("rekey_interval", 100)
    return result


def save_policy(
    path: str | Path,
    policy: dict[str, Any],
    current: dict[str, Any],
    confirm_restrictions: bool = False,
) -> dict[str, Any]:
    """Atomically save a validated next-session policy, without modifying inputs."""
    value = validate_update(policy, current, confirm_restrictions)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return value
