"""Real KEM computation trials; transport measurements require a real transport.

Run ``python -m benchmarks.runner --trials 30 --output artifacts/benchmarks``.
No measurements in this module are substituted for a full protocol handshake.
"""

from __future__ import annotations

import argparse
import os
import json
import math
import platform
import resource
import statistics
import sys
import subprocess
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import psutil

from crypto.primitives import (
    available_algorithms,
    decapsulate,
    encapsulate,
    kem_keypair,
    versions,
)
from policy.engine import PolicyError, load_policy, select

ALGORITHMS = ("ML-KEM-768", "HQC-3")


def summarize(values: list[float]) -> dict[str, float | int]:
    if not values:
        raise ValueError("Cannot summarize an empty trial set")
    ordered = sorted(values)
    return {
        "n": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p95": ordered[max(0, math.ceil(0.95 * len(values)) - 1)],
        "min": min(values),
        "max": max(values),
    }


def _milliseconds(operation: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter_ns()
    result = operation()
    return result, (time.perf_counter_ns() - start) / 1_000_000


def run(
    trials: int = 10,
    output_dir: str | Path | None = None,
    *,
    handshake_factory: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Measure actual primitives and optionally a complete caller-supplied handshake.

    handshake_factory(name) must execute a full authenticated handshake and return
    actual metrics, e.g. handshake_ms, handshake_bytes, message_roundtrip_ms.
    It is called once for an unrecorded warm-up and once per measured trial per
    algorithm. No full-protocol measurements are replaced with KEM-only timings.
    """
    if type(trials) is not int or not 2 <= trials <= 1000:
        raise ValueError("Use an integer trial count from 2 to 1000")
    installed = {
        row["name"]: row for row in available_algorithms() if row.get("available", True)
    }
    process = psutil.Process()
    machine_details = {}
    if sys.platform == "darwin":
        for field, key in (
            ("model_identifier", "hw.model"),
            ("processor", "machdep.cpu.brand_string"),
            ("macos_version", "kern.osproductversion"),
            ("macos_build", "kern.osversion"),
        ):
            machine_details[field] = subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", key], text=True
            ).strip()
        cpu_description = machine_details["processor"]
    else:
        try:
            cpu_description = next(
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            )
        except (OSError, StopIteration):
            cpu_description = platform.processor() or "unavailable"
    cloud_marker = Path("/etc/codex/network-policy.json").is_file()
    environment = {
        "kind": "managed_cloud" if cloud_marker else "local_or_unclassified",
        "cloud_detected": cloud_marker,
        "evidence": "/etc/codex/network-policy.json exists"
        if cloud_marker
        else "No managed-cloud marker detected; OS alone does not prove local/cloud execution",
        "platform": platform.system(),
        "macos_verified_by_this_run": sys.platform == "darwin",
    }
    report: dict[str, Any] = {
        "metadata": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "trials": trials,
            "warmups": 1,
            "primitive_warmups_per_algorithm": 1,
            "protocol_warmups_per_algorithm": 1 if handshake_factory else 0,
            "environment": environment,
            "configuration": getattr(handshake_factory, "metadata", {}),
            "python": sys.version,
            "os": platform.platform(),
            "machine": platform.machine(),
            "processor": cpu_description,
            "machine_details": machine_details,
            "cpu_count": os.cpu_count(),
            "total_memory_bytes": psutil.virtual_memory().total,
            "libraries": versions(),
            "timer": "time.perf_counter_ns",
            "conditions": "Sequential trials; one unrecorded primitive warm-up and, when supplied, one unrecorded full protocol/network callback warm-up per algorithm. Network metrics come only from actual callback exchanges.",
            "memory_method": "RSS sampled after each operation; resource.ru_maxrss cumulative process high-water mark; tracemalloc Python-allocation peak. High-water marks are process-wide and not attributable to one algorithm.",
            "cpu_method": "process_time_ns includes all process threads; CPU usage percent = process CPU / wall time, may exceed 100%.",
            "p95_method": "nearest-rank",
            "status_note": "HQC-3 is experimental; default application policy does not select it.",
        },
        "algorithms": [],
        "selection_measurements": {},
        "limitations": [
            "RSS samples are not a continuous peak-native-memory profiler.",
            "Measurements from concurrent clients may include their worker-thread activity.",
            "No network transmission latency is inferred from cryptographic computation timings.",
        ],
    }
    for name in ALGORITHMS:
        if name not in installed:
            report["algorithms"].append(
                {
                    "name": name,
                    "status": "unavailable",
                    "reason": "Not enabled in the installed liboqs build",
                    "statistics": {},
                    "raw_trials": [],
                }
            )
            continue
        details = installed[name]
        result: dict[str, Any] = {
            "name": name,
            "status": "measured",
            "implementation_status": details.get("status"),
            "security_level": details["security_level"],
            "public_key_bytes": details["public_key_bytes"],
            "ciphertext_bytes": details["ciphertext_bytes"],
            "raw_trials": [],
            "full_handshake": "measured"
            if handshake_factory
            else "unavailable: no full-handshake adapter supplied",
            "network_transmission_ms": None,
        }
        public, secret = kem_keypair(name)
        ciphertext, shared = encapsulate(name, public)
        if decapsulate(name, secret, ciphertext) != shared:
            raise RuntimeError(f"{name}: warm-up key establishment failed")
        warmup_metrics = None
        if handshake_factory:
            warmup_metrics = _validate_handshake_metrics(handshake_factory(name))
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
                (ciphertext, shared), encapsulate_ms = _milliseconds(
                    lambda: encapsulate(name, public)
                )
                rss.append(process.memory_info().rss)
                recovered, decapsulate_ms = _milliseconds(
                    lambda: decapsulate(name, secret, ciphertext)
                )
                rss.append(process.memory_info().rss)
                if recovered != shared:
                    raise RuntimeError(
                        f"{name}: shared secret mismatch on trial {index}"
                    )
                cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
                wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
                _, python_peak = tracemalloc.get_traced_memory()
            finally:
                if not tracing_before:
                    tracemalloc.stop()
            row = {
                "trial": index + 1,
                "keygen_ms": keygen_ms,
                "encapsulate_ms": encapsulate_ms,
                "decapsulate_ms": decapsulate_ms,
                "kem_total_ms": keygen_ms + encapsulate_ms + decapsulate_ms,
                "cpu_ms": cpu_ms,
                "cpu_usage_percent": cpu_ms / max(wall_ms, 1e-9) * 100,
                "peak_rss_bytes": max(rss),
                "rss_growth_bytes": max(rss) - rss[0],
                "process_high_water_rss_bytes": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss
                * (1 if sys.platform == "darwin" else 1024),
                "python_peak_bytes": max(0, python_peak - baseline_python),
                "kem_bandwidth_bytes": len(public) + len(ciphertext),
            }
            if handshake_factory:
                handshake = handshake_factory(name)
                measured = _validate_handshake_metrics(handshake)
                if warmup_metrics is None or measured.keys() != warmup_metrics.keys():
                    raise ValueError(
                        "Handshake metric availability changed between warm-up and measured trials"
                    )
                row.update(measured)
            result["raw_trials"].append(row)
        result["statistics"] = {
            metric: summarize([row[metric] for row in result["raw_trials"]])
            for metric in result["raw_trials"][0]
            if metric != "trial"
        }
        result["malformed_inputs"] = _malformed(name, public, secret, ciphertext)
        performance = {
            key: result["statistics"][key]["mean"]
            for key in ("handshake_ms", "cpu_ms", "peak_rss_bytes", "handshake_bytes")
            if key in result["statistics"]
        }
        # KEM bytes and timings remain separately named when no authenticated adapter is supplied.
        report["selection_measurements"][name] = performance
        report["algorithms"].append(result)
    offer = {
        "algorithms": list(installed),
        "policy": load_policy(),
        "measurements": report["selection_measurements"],
    }
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
    report["findings"] = _findings(report)
    if output_dir is not None:
        write_report(report, Path(output_dir))
    return report


METRICS = (
    "handshake_ms",
    "handshake_bytes",
    "message_roundtrip_ms",
    "encrypt_ms",
    "decrypt_ms",
    "aes_256_gcm_encrypt_ms",
    "aes_256_gcm_decrypt_ms",
    "chacha20_poly1305_encrypt_ms",
    "chacha20_poly1305_decrypt_ms",
    "network_handshake_ms",
    "network_message_roundtrip_ms",
    "relay_transport_roundtrip_ms",
    "rekey_ms",
    "network_rekey_ms",
)


def _validate_handshake_metrics(handshake: Any) -> dict[str, float]:
    if not isinstance(handshake, dict):
        raise ValueError("Handshake adapter must return measured metrics")
    if any(
        handshake.get(metric) is None for metric in ("handshake_ms", "handshake_bytes")
    ):
        raise ValueError(
            "Full handshake adapter must report actual handshake_ms and handshake_bytes"
        )
    output = {}
    for metric in METRICS:
        value = handshake.get(metric)
        if value is not None:
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid handshake metric {metric}")
            output[metric] = value
    return output


def _findings(report):
    observations = []
    for result in report["algorithms"]:
        if result["status"] != "measured":
            observations.append(
                f"{result['name']}: unavailable; no timing comparison was fabricated."
            )
            continue
        summary = result["statistics"]
        observations.append(
            f"{result['name']}: {len(result['raw_trials'])} measured trials; "
            f"mean KEM computation {summary['kem_total_ms']['mean']:.4f} ms."
        )
        for metric, label in [
            ("handshake_ms", "protocol computation handshake"),
            ("network_handshake_ms", "full loopback handshake"),
            ("rekey_ms", "authenticated re-key computation"),
        ]:
            if metric in summary:
                observations.append(
                    f"{result['name']}: mean {label} {summary[metric]['mean']:.4f} ms, "
                    f"nearest-rank P95 {summary[metric]['p95']:.4f} ms."
                )
    observations.append(
        "Measured speed is not evidence of stronger security; HQC-3 remains experimental under the default policy."
    )
    return observations


def _malformed(
    name: str, public: bytes, secret: bytes, ciphertext: bytes
) -> dict[str, str]:
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
        observations["corrupted_ciphertext"] = (
            "implicit rejection: different secret; authenticated handshake confirmation must reject"
        )
    except ValueError:
        observations["corrupted_ciphertext"] = "explicitly rejected by implementation"
    return observations


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    from benchmarks.reporting import write_report as write

    write(report, output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--output", type=Path, default=Path("artifacts/benchmarks"))
    parser.add_argument(
        "--delay-ms",
        type=float,
        default=0,
        help="Artificial per-send delay at loopback test endpoints",
    )
    parser.add_argument(
        "--primitives-only",
        action="store_true",
        help="Explicitly omit full protocol/network measurements",
    )
    args = parser.parse_args()
    directory = None
    try:
        if args.primitives_only:
            completed = run(args.trials, args.output)
        else:
            from benchmarks.protocol_adapter import factory

            callback, directory = factory(delay_ms=args.delay_ms)
            completed = run(args.trials, args.output, handshake_factory=callback)
    finally:
        if directory is not None:
            directory.cleanup()
    print(
        json.dumps(
            {
                "output": str(args.output),
                "algorithms": [
                    {"name": row["name"], "status": row["status"]}
                    for row in completed["algorithms"]
                ],
            },
            indent=2,
        )
    )
