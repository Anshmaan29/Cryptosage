"""Real full-protocol benchmarks, export integrity and bounded delay validation."""

import csv
import json
import zipfile

import pytest

from benchmarks.protocol_adapter import factory
from benchmarks.runner import run, summarize, _validate_handshake_metrics
from benchmarks.transport import validate_delay


@pytest.mark.parametrize("value", [True, -1, 1001, float("nan"), float("inf"), "20"])
def test_delay_configuration_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="delay"):
        validate_delay(value)


@pytest.mark.parametrize("trials", [True, 0, 1, 1001, 30.0, "300"])
def test_trial_count_is_strict_and_bounded(trials):
    with pytest.raises(ValueError, match="trial count"):
        run(trials)


def test_nearest_rank_percentiles_use_observed_values():
    result = summarize(list(range(1, 101)))
    assert result["p95"] == 95
    assert result["mean"] == 50.5
    assert result["n"] == 100


def test_missing_or_invalid_callback_metrics_cannot_claim_measured_handshake():
    with pytest.raises(ValueError, match="actual handshake"):
        _validate_handshake_metrics({})
    with pytest.raises(ValueError, match="Invalid handshake metric"):
        _validate_handshake_metrics(
            {"handshake_ms": float("nan"), "handshake_bytes": 12}
        )


def test_full_callback_has_unrecorded_warmup_and_real_rekey():
    callback, directory = factory(include_network=False)
    calls = []

    def measured(name):
        calls.append(name)
        return callback(name)

    measured.metadata = callback.metadata
    try:
        result = run(2, handshake_factory=measured)
    finally:
        directory.cleanup()
    for algorithm in result["algorithms"]:
        assert algorithm["status"] == "measured"
        assert calls.count(algorithm["name"]) == 3
        assert len(algorithm["raw_trials"]) == 2
        assert algorithm["statistics"]["rekey_ms"]["n"] == 2
        assert algorithm["statistics"]["handshake_ms"]["mean"] > 0
        assert algorithm["statistics"]["handshake_bytes"]["min"] > 0
        assert "network_handshake_ms" not in algorithm["statistics"]
        for cipher in ("aes_256_gcm", "chacha20_poly1305"):
            for operation in ("encrypt", "decrypt"):
                metric = algorithm["statistics"][f"{cipher}_{operation}_ms"]
                assert metric["n"] == 2 and metric["min"] > 0
    assert result["metadata"]["protocol_warmups_per_algorithm"] == 1
    assert result["metadata"]["configuration"]["network_enabled"] is False
    assert result["metadata"]["environment"]["kind"] in {
        "managed_cloud",
        "local_or_unclassified",
    }


def test_loopback_delay_measurement_and_rekey_are_real():
    callback, directory = factory(delay_ms=3)
    try:
        result = callback("ML-KEM-768")
    finally:
        directory.cleanup()
    assert result["network_handshake_ms"] >= 12
    assert result["network_rekey_ms"] >= 12
    assert result["relay_transport_roundtrip_ms"] >= 6
    assert callback.metadata["injected_send_delay_ms"] == 3
    assert "not observed LAN/WAN" in callback.metadata["network_condition"]


def test_report_exports_real_rows_charts_and_standalone_html(tmp_path):
    callback, directory = factory(include_network=False)
    try:
        result = run(2, tmp_path, handshake_factory=callback)
    finally:
        directory.cleanup()
    saved = json.loads((tmp_path / "results.json").read_text())
    assert saved == result
    with (tmp_path / "trials.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    assert all(float(row["handshake_ms"]) > 0 for row in rows)
    document = (tmp_path / "report.html").read_text()
    assert document.count("<svg") == 6
    assert "<script" not in document
    assert "nearest-rank P95" in document
    assert "managed_cloud" in document or "local_or_unclassified" in document
    with zipfile.ZipFile(tmp_path / "report.zip") as archive:
        assert {
            "report.html",
            "results.json",
            "trials.csv",
            "network-delay.svg",
            "resources.png",
        } <= set(archive.namelist())
        assert all("/" not in name and ".." not in name for name in archive.namelist())
        assert json.loads(archive.read("results.json")) == result


def test_named_network_profiles_validate_and_record_constrained_transport():
    with pytest.raises(ValueError, match="named network profile"):
        factory(profile="constrained", delay_ms=1)
    callback, directory = factory(profile="constrained")
    try:
        result = callback("ML-KEM-768")
    finally:
        directory.cleanup()
    assert callback.metadata["simulated_bandwidth_bps"] == 256_000
    assert not callback.metadata["packet_loss_injected"]
    minimum_ms = 4 * 100 + 8 * result["handshake_bytes"] / 256
    assert result["network_handshake_ms"] >= minimum_ms
