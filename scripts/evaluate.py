"""Run pytest and publish only this invocation's recorded JUnit outcomes."""

from __future__ import annotations

import html
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


OUTCOMES = ("passed", "failed", "error", "skipped", "xfailed")


def parse_outcomes(path: Path, exit_code: int) -> dict:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runner_exit": exit_code,
        "counts": {outcome: 0 for outcome in OUTCOMES},
        "tests": [],
        "source": "JUnit XML from this pytest invocation",
        "complete": False,
    }
    if not path.is_file():
        report["diagnostic"] = (
            "Runner produced no JUnit output; evaluation is incomplete."
        )
        return report
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        report["diagnostic"] = (
            "Runner produced malformed JUnit output; evaluation is incomplete."
        )
        return report
    for case in tree.iter("testcase"):
        failure, error, skipped = (
            case.find("failure"),
            case.find("error"),
            case.find("skipped"),
        )
        if error is not None:
            outcome, detail = (
                "error",
                "Test infrastructure or collection error; inspect local pytest output.",
            )
        elif failure is not None:
            outcome, detail = (
                "failed",
                "Test assertions failed; inspect local pytest output.",
            )
        elif skipped is not None:
            outcome = "xfailed" if skipped.get("type") == "pytest.xfail" else "skipped"
            detail = (
                "Expected failure recorded by pytest."
                if outcome == "xfailed"
                else "Test did not execute its full assertions."
            )
        else:
            outcome, detail = (
                "passed",
                "Test assertions completed without a reported failure.",
            )
        label = case.get("classname", "") + "." + case.get("name", "")
        report["counts"][outcome] += 1
        report["tests"].append(
            {
                "name": label,
                "expected": case.get("name", "")
                .removeprefix("test_")
                .replace("_", " "),
                "observed": detail,
                "status": outcome,
                "duration_seconds": case.get("time", "unavailable"),
            }
        )
    report["complete"] = bool(report["tests"]) and exit_code in (0, 1)
    if not report["tests"]:
        report["diagnostic"] = "Zero recorded tests do not validate the application."
    return report


def write_reports(report: dict, directory: Path) -> None:
    summary = "; ".join(f"{name}: {report['counts'][name]}" for name in OUTCOMES)
    lines = [
        "# Automated security and functional evaluation",
        "",
        "Generated: " + report["generated_at"],
        "",
        f"{summary}. Runner exit: {report['runner_exit']}. Complete: {report['complete']}.",
        "",
        "Recorded runner outcomes apply to the tested revision. Passing tests do not constitute formal protocol verification or production certification.",
        "",
        "| Test | Expected behavior | Observed result | Outcome |",
        "| --- | --- | --- | --- |",
    ]
    for row in report["tests"]:
        values = [row["name"], row["expected"], row["observed"], row["status"].upper()]
        lines.append(
            "| "
            + " | ".join(value.replace("|", "/").replace("\n", " ") for value in values)
            + " |"
        )
    if report.get("diagnostic"):
        lines += ["", report["diagnostic"]]
    (directory / "security-tests.md").write_text("\n".join(lines) + "\n")
    (directory / "security-tests.json").write_text(json.dumps(report, indent=2) + "\n")
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(row[key]))}</td>"
            for key in ("name", "expected", "observed", "status")
        )
        + "</tr>"
        for row in report["tests"]
    )
    document = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Crytosage security evaluation</title><style>body{margin:0;background:#f5f5ef;color:#183b30;font:16px/1.6 system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:40px 24px}h1{font-size:2rem}p{max-width:82ch}table{border-collapse:collapse;width:100%;background:#fff}th,td{text-align:left;vertical-align:top;padding:12px;border:1px solid #c8d1c6;overflow-wrap:anywhere}th{background:#214d3f;color:#fff}.table{overflow:auto}@media print{main{padding:0}table{font-size:10px}}</style><main><p>Crytosage / recorded evaluation</p><h1>Security and functional test report</h1>"""
    document += f"<p>Generated {html.escape(report['generated_at'])}</p><p>{html.escape(summary)}. Runner exit: {report['runner_exit']}. Complete: {report['complete']}.</p>"
    document += "<p>Each row is a recorded pytest outcome. Failure details remain in the local runner output to avoid exporting sensitive assertion values. Passing tests demonstrate only the exercised behavior; they are not formal protocol verification or production certification.</p>"
    if report.get("diagnostic"):
        document += "<p>" + html.escape(report["diagnostic"]) + "</p>"
    document += (
        '<div class="table"><table><thead><tr><th>Test</th><th>Expected behavior</th><th>Observed result</th><th>Outcome</th></tr></thead><tbody>'
        + rows
        + "</tbody></table></div></main></html>"
    )
    (directory / "security-tests.html").write_text(document)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    directory = root / "reports"
    directory.mkdir(exist_ok=True)
    xml = directory / "tests.xml"
    xml.unlink(missing_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", f"--junitxml={xml}", *sys.argv[1:]],
        cwd=root,
    )
    write_reports(parse_outcomes(xml, result.returncode), directory)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
