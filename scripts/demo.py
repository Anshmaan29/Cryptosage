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

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / ".runtime" / "demo-process.json"
LOCK = ROOT / ".runtime" / "demo-launch.lock"


def process_fingerprint(pid: int) -> str | None:
    """POSIX ps fields work on Linux and macOS; no process environment is read."""
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "uid=", "-o", "lstart=", "-o", "command="],
        capture_output=True,
        text=True,
        check=False,
    )
    return " ".join(result.stdout.split()) if result.returncode == 0 else None


def read_record() -> dict[str, Any] | None:
    if not RECORD.exists():
        return None
    if RECORD.is_symlink() or RECORD.stat().st_mode & 0o077:
        raise ValueError(
            "Unsafe demo PID record; inspect its ownership and permissions"
        )
    value = json.loads(RECORD.read_text())
    if (
        not isinstance(value, dict)
        or type(value.get("pid")) is not int
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
    for port in (8001, 8002, 8765):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise ValueError(
                    f"Port {port} is occupied. Stop its owner before launching the demo."
                ) from exc


def launch() -> int:
    RECORD.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = read_record()
    if record and recorded_launcher_alive(record):
        raise ValueError(
            "A recorded demo is already running; use ./scripts/stop_demo.sh first"
        )
    if LOCK.exists():
        if record is None:
            raise ValueError(
                "Demo launch lock exists without a PID record; inspect .runtime before removal"
            )
        LOCK.rmdir()
    LOCK.mkdir(mode=0o700)
    children: list[subprocess.Popen[bytes]] = []
    try:
        check_ports()
        fingerprint = process_fingerprint(os.getpid())
        if fingerprint is None:
            raise ValueError("Cannot record launcher identity: ps is unavailable")
        fd = os.open(RECORD, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"pid": os.getpid(), "fingerprint": fingerprint}, handle)
        subprocess.run(
            [sys.executable, "-m", "scripts.init_demo"], cwd=ROOT, check=True
        )
        commands = [
            ["server.relay"],
            ["client.app", "--name", "Alice", "--port", "8001"],
            ["client.app", "--name", "Bob", "--port", "8002"],
        ]
        for command in commands:
            children.append(
                subprocess.Popen([sys.executable, "-m", *command], cwd=ROOT)
            )
        print(
            "Alice port 8001; Bob port 8002; ciphertext relay port 8765. Ctrl-C stops this demo.",
            flush=True,
        )

        def shutdown(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, shutdown)
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
        LOCK.rmdir()


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
