from benchmarks.runner import summarize


def test_statistics_use_nearest_rank_p95_and_sample_stdev():
    summary = summarize([1.0, 2.0, 3.0, 4.0])
    assert summary["n"] == 4
    assert summary["mean"] == summary["median"] == 2.5
    assert summary["p95"] == 4.0
    assert summary["min"] == 1.0 and summary["max"] == 4.0
    assert 1.29 < summary["stdev"] < 1.30
