from client.reports import test_results as recorded_results


def test_absent_report_is_not_a_passing_report(tmp_path):
    result = recorded_results(tmp_path / "missing.xml")
    assert result["test_report_status"] == "not_run"
    assert result["tests"] == []


def test_actual_junit_outcomes_remain_distinct(tmp_path):
    p = tmp_path / "tests.xml"
    p.write_text(
        '<testsuite><testcase name="test_valid"/><testcase name="test_bad"><failure/></testcase><testcase name="test_skip"><skipped/></testcase></testsuite>'
    )
    result = recorded_results(p)
    assert [test["status"] for test in result["tests"]] == [
        "passed",
        "failed",
        "skipped",
    ]
    assert result["test_report_status"] == "recorded"


def test_report_reader_rejects_xml_with_dtd(tmp_path):
    p = tmp_path / "tests.xml"
    p.write_text(
        '<!DOCTYPE testsuite [<!ENTITY payload "untrusted">]><testsuite>&payload;</testsuite>'
    )
    assert recorded_results(p) == {"tests": [], "test_report_status": "invalid_report"}
