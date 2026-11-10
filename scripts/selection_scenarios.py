"""Record decisions from the native selector using observed handshake measurements."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
from statistics import median

from benchmarks.protocol_adapter import factory
from crypto.primitives import versions
from policy.engine import PolicyError, admissible_algorithms, load_policy, select


def run(output: Path) -> dict:
    measure, directory = factory(include_network=False)
    try:
        trials = {
            name: [measure(name) for _ in range(5)]
            for name in ("ML-KEM-768", "ML-KEM-1024")
        }
    finally:
        directory.cleanup()
    measured = {
        name: {
            metric: median(row[metric] for row in rows)
            for metric in ("handshake_ms", "handshake_bytes")
        }
        for name, rows in trials.items()
    }

    def make(
        *,
        minimum=3,
        experimental=False,
        preference="latency",
        only=None,
        enable_512=False,
    ):
        policy = load_policy()
        policy.update(
            minimum_security_level=minimum,
            allow_experimental=experimental,
            performance_preference=preference,
        )
        if only is not None:
            for name, rule in policy["algorithms"].items():
                if name not in only:
                    rule["status"] = "prohibited"
        if enable_512:
            policy["algorithms"]["ML-KEM-512"]["status"] = "recommended"
        return policy

    cases = [
        ("Default policies", make(), make(), False),
        ("Minimum level 5", make(minimum=5), make(), False),
        ("Only Alice opts in", make(experimental=True), make(), False),
        (
            "Both opt in, ML-KEM prohibited",
            make(experimental=True, only={"HQC-3", "HQC-5"}),
            make(experimental=True, only={"HQC-3", "HQC-5"}),
            False,
        ),
        (
            "Bandwidth and latency with observed measurements",
            make(preference="bandwidth"),
            make(),
            True,
        ),
        (
            "ML-KEM-512 allowed with level 3 minimum",
            make(enable_512=True),
            make(enable_512=True),
            False,
        ),
        (
            "Incompatible KEM restrictions",
            make(only={"ML-KEM-768"}),
            make(only={"ML-KEM-1024"}),
            False,
        ),
        ("Observed latency among equal-priority ML-KEMs", make(), make(), True),
    ]

    def offer(policy: dict) -> dict:
        return {"policy": policy, "algorithms": admissible_algorithms(policy)}

    def summary(policy: dict) -> str:
        enabled = ", ".join(admissible_algorithms(policy)) or "none"
        opt_in = "on" if policy["allow_experimental"] else "off"
        return f"Level {policy['minimum_security_level']}, experimental {opt_in}, {policy['performance_preference']}. Offered {enabled}."

    scenarios: list[dict] = []
    for label, alice, bob, uses_measurements in cases:
        try:
            result = select(
                offer(alice), offer(bob), measured if uses_measurements else None
            )
            chosen, reason, decision = (
                result["algorithm"],
                result["reason"],
                result["decision"],
            )
        except PolicyError as exc:
            chosen, reason, decision = None, str(exc), exc.decision
        scenarios.append(
            {
                "scenario": label,
                "alice": summary(alice),
                "bob": summary(bob),
                "eligible": [
                    row["name"] for row in decision["candidates"] if row["eligible"]
                ],
                "chosen": chosen,
                "reason": reason,
                "performance": decision["performance"],
            }
        )
    report: dict = {
        "machine": platform.machine(),
        "os": platform.platform(),
        "versions": versions(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measurement_method": "Median of five direct authenticated handshakes per KEM. No network simulation.",
        "trials": trials,
        "measurements": measured,
        "scenarios": scenarios,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "selection-scenarios.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    lines = [
        "# Native KEM selection scenarios",
        "",
        f"{report['os']}, Python {report['versions']['python']}, liboqs {report['versions']['liboqs']} ({report['versions']['liboqs_commit']}).",
        report["measurement_method"],
        "",
        "| Scenario | Alice | Bob | Eligible | Choice | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in scenarios:
        cells = (
            row["scenario"],
            row["alice"],
            row["bob"],
            ", ".join(row["eligible"]) or "None",
            row["chosen"] or "Refused",
            row["reason"],
        )
        lines.append("| " + " | ".join(cells) + " |")
    (output / "selection-scenarios.md").write_text("\n".join(lines) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports/final"))
    run(parser.parse_args().output)
