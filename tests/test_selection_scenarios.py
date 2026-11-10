import json
import subprocess
import sys

from policy.engine import KNOWN, installed_algorithms


def test_native_kem_catalog_matches_the_documented_levels():
    assert {
        name: row["security_level"] for name, row in installed_algorithms().items()
    } == KNOWN


def test_selection_scenarios_cli_uses_real_handshake_measurements(tmp_path):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.selection_scenarios",
            "--output",
            str(tmp_path),
        ],
        check=True,
    )
    report = json.loads((tmp_path / "selection-scenarios.json").read_text())
    rows = report["scenarios"]
    assert len(rows) == 8
    assert rows[0]["chosen"] == "ML-KEM-768"
    assert "static size from library, not a measurement" in rows[0]["reason"]
    assert rows[1]["chosen"] == "ML-KEM-1024"
    assert "HQC-3" not in rows[2]["eligible"]
    assert rows[3]["chosen"] == "HQC-3"
    assert "ML-KEM-512" not in rows[5]["eligible"]
    assert rows[6]["chosen"] is None
    assert rows[7]["performance"]["metrics"] == ["handshake_ms"]
    assert all(
        len(trials) == 5 and all(row["handshake_ms"] > 0 for row in trials)
        for trials in report["trials"].values()
    )
    assert (tmp_path / "selection-scenarios.md").exists()
