"""Read only recorded pytest outcomes; never run tests from a browser request."""

from datetime import datetime, timezone
from pathlib import Path
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


def test_results(path: Path) -> dict:
    if not path.is_file():
        return {"tests": [], "test_report_status": "not_run"}
    try:
        root = ET.parse(path, forbid_dtd=True)
    except (ET.ParseError, DefusedXmlException):
        return {"tests": [], "test_report_status": "invalid_report"}
    tests = []
    for case in root.iter("testcase"):
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        status = "failed" if failed else "skipped" if skipped else "passed"
        tests.append(
            {
                "name": case.get("classname", "") + "." + case.get("name", ""),
                "expected": case.get("name", "")
                .removeprefix("test_")
                .replace("_", " "),
                "observed": "Assertions completed"
                if status == "passed"
                else "See local security report",
                "status": status,
            }
        )
    return {
        "tests": tests,
        "test_report_status": "recorded",
        "test_report_time": datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc
        ).isoformat(),
        "test_report_note": "Recorded run, not a live assertion about subsequent source changes.",
    }
