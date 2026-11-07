"""Real KEM computation trials; transport measurements require a real transport.

Run ``python -m benchmarks.runner --trials 30 --output artifacts/benchmarks``.
No measurements in this module are substituted for a full protocol handshake.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import resource
import statistics
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import psutil

from crypto.primitives import available_algorithms, decapsulate, encapsulate, kem_keypair, versions
from policy.engine import PolicyError, load_policy, select

ALGORITHMS = ("ML-KEM-768", "HQC-3")


def summarize(values: list[float]) -> dict[str, float | int]:
    if not values:
        raise ValueError("Cannot summarize an empty trial set")
    ordered = sorted(values)
    return {"n": len(values), "mean": statistics.mean(values),
            "median": statistics.median(values), "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "p95": ordered[max(0, math.ceil(0.95 * len(values)) - 1)], "min": min(values), "max": max(values)}


def _milliseconds(operation: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter_ns()
    result = operation()
    return result, (time.perf_counter_ns() - start) / 1_000_000


def run(trials: int = 10, output_dir: str | Path | None = None,
        *, handshake_factory: Callable[[str], dict[str, Any]] | None = None) -> dict[str, Any]:
    """Measure actual primitives and optionally a complete caller-supplied handshake.

    handshake_factory(name) must execute a full authenticated handshake and return
    actual metrics, e.g. handshake_ms, handshake_bytes, message_roundtrip_ms.
    It is called once per measured trial, never replaced with KEM-only timings.
    """
    if type(trials) is not int or not 2 <= trials <= 1000:
        raise ValueError("Use an integer trial count from 2 to 1000")
    installed = {row["name"]: row for row in available_algorithms() if row.get("available", True)}
    process = psutil.Process()
    try:
        cpu_description = next(line.split(":", 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                               if line.startswith('model name'))
    except (OSError, StopIteration):
        cpu_description = platform.processor() or "unavailable"
    report: dict[str, Any] = {
        "metadata": {"created_at": datetime.now(timezone.utc).isoformat(), "trials": trials,
                     "warmups": 1, "python": sys.version, "os": platform.platform(),
                     "machine": platform.machine(), "processor": cpu_description,
                     "cpu_count": os.cpu_count(), "total_memory_bytes": psutil.virtual_memory().total,
                     "libraries": versions(), "timer": "time.perf_counter_ns",
                     "conditions": "Sequential local trials; one unrecorded warm-up per algorithm; no network timings inferred.",
                     "memory_method": "RSS sampled after each operation; resource.ru_maxrss cumulative process high-water mark; tracemalloc Python-allocation peak. High-water marks are process-wide and not attributable to one algorithm.",
                     "cpu_method": "process_time_ns includes all process threads; CPU usage percent = process CPU / wall time, may exceed 100%.",
                     "p95_method": "nearest-rank", "status_note": "HQC-3 is experimental; default application policy does not select it."},
        "algorithms": [], "selection_measurements": {},
        "limitations": ["RSS samples are not a continuous peak-native-memory profiler.",
                        "Measurements from concurrent clients may include their worker-thread activity.",
                        "No network transmission latency is inferred from cryptographic computation timings."]}
    for name in ALGORITHMS:
        if name not in installed:
            report["algorithms"].append({"name": name, "status": "unavailable",
                                         "reason": "Not enabled in the installed liboqs build", "statistics": {}, "raw_trials": []})
            continue
        details = installed[name]
        result: dict[str, Any] = {"name": name, "status": "measured", "implementation_status": details.get("status"),
                                  "security_level": details["security_level"],
                                  "public_key_bytes": details["public_key_bytes"],
                                  "ciphertext_bytes": details["ciphertext_bytes"], "raw_trials": [],
                                  "full_handshake": "measured" if handshake_factory else "unavailable: no full-handshake adapter supplied",
                                  "network_transmission_ms": None}
        public, secret = kem_keypair(name)
        ciphertext, shared = encapsulate(name, public)
        if decapsulate(name, secret, ciphertext) != shared:
            raise RuntimeError(f"{name}: warm-up key establishment failed")
        for index in range(trials):
            rss = [process.memory_info().rss]
            tracing_before = tracemalloc.is_tracing()
            if not tracing_before:
                tracemalloc.start()
            baseline_python, _ = tracemalloc.get_traced_memory()
            if not tracing_before:
                tracemalloc.reset_peak()
            cpu_start = time.process_time_ns()
            wall_start = time.perf_counter_ns()
            try:
                (public, secret), keygen_ms = _milliseconds(lambda: kem_keypair(name))
                rss.append(process.memory_info().rss)
                (ciphertext, shared), encapsulate_ms = _milliseconds(lambda: encapsulate(name, public))
                rss.append(process.memory_info().rss)
                recovered, decapsulate_ms = _milliseconds(lambda: decapsulate(name, secret, ciphertext))
                rss.append(process.memory_info().rss)
                if recovered != shared:
                    raise RuntimeError(f"{name}: shared secret mismatch on trial {index}")
                cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
                wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
                _, python_peak = tracemalloc.get_traced_memory()
            finally:
                if not tracing_before:
                    tracemalloc.stop()
            row = {"trial": index + 1, "keygen_ms": keygen_ms, "encapsulate_ms": encapsulate_ms,
                   "decapsulate_ms": decapsulate_ms, "kem_total_ms": keygen_ms + encapsulate_ms + decapsulate_ms,
                   "cpu_ms": cpu_ms, "cpu_usage_percent": cpu_ms / max(wall_ms, 1e-9) * 100,
                   "peak_rss_bytes": max(rss), "rss_growth_bytes": max(rss) - rss[0],
                   "process_high_water_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                   "python_peak_bytes": max(0, python_peak - baseline_python),
                   "kem_bandwidth_bytes": len(public) + len(ciphertext)}
            if handshake_factory:
                handshake = handshake_factory(name)
                if not isinstance(handshake, dict):
                    raise ValueError("Handshake adapter must return measured metrics")
                for metric in ("handshake_ms", "handshake_bytes", "message_roundtrip_ms", "encrypt_ms", "decrypt_ms", "network_handshake_ms", "network_message_roundtrip_ms", "relay_transport_roundtrip_ms"):
                    value = handshake.get(metric)
                    if value is not None:
                        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                            raise ValueError(f"Invalid handshake metric {metric}")
                        row[metric] = value
            result["raw_trials"].append(row)
        result["statistics"] = {metric: summarize([row[metric] for row in result["raw_trials"]])
                                for metric in result["raw_trials"][0] if metric != "trial"}
        result["malformed_inputs"] = _malformed(name, public, secret, ciphertext)
        performance = {key: result["statistics"][key]["mean"]
                       for key in ("handshake_ms", "cpu_ms", "peak_rss_bytes", "handshake_bytes")
                       if key in result["statistics"]}
        # KEM bytes and timings remain separately named when no authenticated adapter is supplied.
        report["selection_measurements"][name] = performance
        report["algorithms"].append(result)
    offer = {"algorithms": list(installed), "policy": load_policy(), "measurements": report["selection_measurements"]}
    selection_samples = []
    selection_outcome = None
    for _ in range(trials):
        started = time.perf_counter_ns()
        try:
            decision = select(offer, offer)
            selection_outcome = {"status": "selected", **decision}
        except PolicyError as exc:
            selection_outcome = {"status": "rejected", "reason": str(exc)}
        selection_samples.append((time.perf_counter_ns() - started) / 1_000_000)
    report["selection_overhead_ms"] = summarize(selection_samples)
    report["selection_outcome"] = selection_outcome
    if output_dir is not None:
        write_report(report, Path(output_dir))
    return report


def _malformed(name: str, public: bytes, secret: bytes, ciphertext: bytes) -> dict[str, str]:
    observations = {}
    for label, operation in {
        "truncated_public_key": lambda: encapsulate(name, public[:-1]),
        "truncated_ciphertext": lambda: decapsulate(name, secret, ciphertext[:-1]),
        "truncated_secret_key": lambda: decapsulate(name, secret[:-1], ciphertext),
    }.items():
        try:
            operation()
        except (ValueError, RuntimeError) as exc:
            observations[label] = f"rejected: {type(exc).__name__}"
        else:
            raise RuntimeError(f"{name}: {label} was not rejected")
    altered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    try:
        candidate = decapsulate(name, secret, altered)
        original = decapsulate(name, secret, ciphertext)
        if candidate == original:
            raise RuntimeError(f"{name}: modified ciphertext recovered original secret")
        observations["corrupted_ciphertext"] = "implicit rejection: different secret; authenticated handshake confirmation must reject"
    except ValueError:
        observations["corrupted_ciphertext"] = "explicitly rejected by implementation"
    return observations


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = [{"algorithm": result["name"], **trial} for result in report["algorithms"]
            for trial in result.get("raw_trials", [])]
    columns = ["algorithm", "trial"] + sorted({key for row in rows for key in row} - {"algorithm", "trial"})
    with (output_dir / "trials.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    _plot(report, output_dir)


def _plot(report: dict[str, Any], output_dir: Path) -> None:
    os.environ.setdefault('MPLCONFIGDIR', str(output_dir.resolve() / '.matplotlib-cache'))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    rows = [{"Algorithm": result["name"], "Operation": label, "Mean (ms)": result["statistics"][metric]["mean"],
             "Std dev (ms)": result["statistics"][metric]["stdev"]}
            for result in report["algorithms"] if result["status"] == "measured"
            for label, metric in (("Key generation", "keygen_ms"), ("Encapsulation", "encapsulate_ms"), ("Decapsulation", "decapsulate_ms"))]
    if not rows:
        return
    frame = pd.DataFrame(rows)
    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.spines.top": False, "axes.spines.right": False})
    fig, ax = plt.subplots(figsize=(9, 4.5), layout="constrained")
    means = frame.pivot(index="Operation", columns="Algorithm", values="Mean (ms)")
    errors = frame.pivot(index="Operation", columns="Algorithm", values="Std dev (ms)")
    means.plot.bar(ax=ax, yerr=errors, color=["#204c3a", "#b17a3e"], capsize=3, rot=0)
    ax.set_title(f"Level-3 KEM computation · {report['metadata']['trials']} trials")
    ax.set_ylabel("Latency (ms), mean ± sample standard deviation")
    ax.set_xlabel("")
    ax.legend(title="Installed identifier")
    fig.savefig(output_dir / "kem-latency.png", dpi=180)
    fig.savefig(output_dir / "kem-latency.svg")
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--output", type=Path, default=Path("artifacts/benchmarks"))
    args = parser.parse_args()
    completed = run(args.trials, args.output)
    print(json.dumps({"output": str(args.output), "algorithms": [{"name": row["name"], "status": row["status"]}
                                                                for row in completed["algorithms"]]}, indent=2))
