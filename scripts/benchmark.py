"""Real full protocol and KEM comparison, without inferring network latency."""

import argparse
from benchmarks.runner import run
from benchmarks.protocol_adapter import factory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trials", type=int, default=30)
    p.add_argument("--output", default="reports/benchmarks")
    p.add_argument(
        "--delay-ms",
        type=float,
        default=0,
        help="Artificial endpoint delay per WebSocket send (0–250 ms)",
    )
    a = p.parse_args()
    if not 2 <= a.trials <= 1000:
        p.error("--trials must be from 2 to 1000")
    if not 0 <= a.delay_ms <= 250:
        p.error("--delay-ms must be from 0 to 250")
    callback, directory = factory(delay_ms=a.delay_ms)
    try:
        report = run(a.trials, a.output, handshake_factory=callback)
    finally:
        directory.cleanup()
    for item in report["algorithms"]:
        print(
            item["name"],
            item["status"],
            item.get("statistics", {})
            .get("handshake_ms", {})
            .get("mean", "unavailable"),
        )
    print("Saved real measurements and graphs to", a.output)


if __name__ == "__main__":
    main()
