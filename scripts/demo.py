"""Foreground demo supervisor; stop only a verified launcher it recorded."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from client.storage import atomic_private_write, private_lock, read_private
from scripts.diagnose import main as diagnose

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("CRYTOSAGE_DEMO_ROOT", ROOT / ".runtime")).resolve()
RECORD = DATA / "demo-process.json"
LOCK = DATA / "demo-launch.lockfile"


def process_fingerprint(pid: int) -> str | None:
    """POSIX ps fields work on Linux and macOS; no process environment is read."""
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "lstart=", "-o", "command="],
        capture_output=True,
        text=True,
        check=False,
    )
    fingerprint = " ".join(result.stdout.split())
    if (
        result.returncode != 0
        or not fingerprint.startswith(f"{os.getuid()} ")
        or not fingerprint.endswith(" -m scripts.demo launch")
    ):
        return None
    return fingerprint


def read_record() -> dict[str, Any] | None:
    if not RECORD.exists() and not RECORD.is_symlink():
        return None
    value = json.loads(read_private(RECORD, 4096))
    if (
        not isinstance(value, dict)
        or type(value.get("pid")) is not int
        or value["pid"] <= 1
        or not isinstance(value.get("fingerprint"), str)
    ):
        raise ValueError("Malformed demo process record; inspect it before removal")
    return value


def recorded_launcher_alive(record: dict[str, Any]) -> bool:
    return process_fingerprint(record["pid"]) == record["fingerprint"]


def stop() -> int:
    record = read_record()
    if record is None:
        print(
            "No recorded demo launcher. Independently started components are left running."
        )
        return 0
    if not recorded_launcher_alive(record):
        print("Recorded launcher is gone or its PID was reused. No signal was sent.")
        return 0
    os.kill(record["pid"], signal.SIGTERM)
    for _ in range(100):
        if not recorded_launcher_alive(record):
            print("Recorded demo launcher stopped.")
            return 0
        time.sleep(0.05)
    print(
        "Launcher is still shutting down; no unrelated processes were signalled.",
        file=sys.stderr,
    )
    return 1


def check_ports() -> None:
    for port in (8001, 8002, 8765, 8766):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise ValueError(
                    f"Port {port} is occupied. Stop its owner before launching the demo."
                ) from exc


def launch() -> int:
    with private_lock(LOCK, "A demo launcher is already running"):
        return launch_components()


def launch_components() -> int:
    record = read_record()
    if record and recorded_launcher_alive(record):
        raise ValueError(
            "A recorded demo is already running; use ./scripts/stop_demo.sh first"
        )
    children: list[subprocess.Popen[bytes]] = []
    try:
        check_ports()
        if diagnose():
            raise ValueError("Dependency checks failed; run ./scripts/setup.sh")
        fingerprint = process_fingerprint(os.getpid())
        if fingerprint is None:
            raise ValueError("Cannot record launcher identity: ps is unavailable")
        atomic_private_write(
            RECORD,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "fingerprint": fingerprint,
                }
            ).encode(),
        )

        def shutdown(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, shutdown)
        subprocess.run(
            [sys.executable, "-m", "scripts.init_demo", "--root", str(DATA)],
            cwd=ROOT,
            check=True,
        )
        commands = [["server.relay", "--observe-port", "8766"]]
        for name, port in (("Alice", "8001"), ("Bob", "8002")):
            commands.append(
                [
                    "client.app",
                    "--name",
                    name,
                    "--port",
                    port,
                    "--data-dir",
                    str(DATA / name),
                    "--contacts-dir",
                    str(DATA / "contacts"),
                ]
            )
        for command in commands:
            children.append(
                subprocess.Popen([sys.executable, "-m", *command], cwd=ROOT)
            )
        print(
            "Alice http://127.0.0.1:8001  Bob http://127.0.0.1:8002\nRelay view http://127.0.0.1:8766\nCtrl-C stops this demo.",
            flush=True,
        )

        while all(child.poll() is None for child in children):
            time.sleep(0.2)
        print(
            "A required demo component exited; inspect its startup error above.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        RECORD.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["launch", "stop"])
    args = parser.parse_args()
    try:
        return launch() if args.action == "launch" else stop()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Demo diagnostic: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
