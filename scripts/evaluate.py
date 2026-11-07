"""Execute pytest and derive a security report from this run's JUnit outcomes."""
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    root = Path(__file__).resolve().parents[1]
    directory = root/'reports'
    directory.mkdir(exist_ok=True)
    xml = directory/'tests.xml'
    xml.unlink(missing_ok=True)
    result = subprocess.run([sys.executable,'-m','pytest','-q',f'--junitxml={xml}',*sys.argv[1:]],cwd=root)
    lines = ['# Automated security and functional evaluation','',
             'Generated: '+datetime.now(timezone.utc).isoformat(),'',
             'Results below are parsed from this invocation’s pytest JUnit file. Expected behavior is described by each test’s name and assertions.', '',
             '| Test / expected behavior | Observed result | Outcome |','| --- | --- | --- |']
    counts = {'passed':0,'failed':0,'skipped':0}
    if xml.exists():
        for case in ET.parse(xml).iter('testcase'):
            failure = case.find('failure')
            error = case.find('error')
            skipped = case.find('skipped')
            node = failure if failure is not None else error
            outcome = 'failed' if node is not None else 'skipped' if skipped is not None else 'passed'
            counts[outcome] += 1
            detail = node.get('message','Assertion failed') if node is not None else skipped.get('message','Skipped') if skipped is not None else 'Assertions completed'
            detail = detail.replace('|','/').replace('\n',' ')[:300]
            label = case.get('classname','')+'.'+case.get('name','')
            lines.append(f'| `{label}` | {detail} | {outcome.upper()} |')
    else:
        lines += ['', 'No JUnit output was produced. Evaluation did not complete.']
    lines += ['', f'Passed: {counts["passed"]}; failed: {counts["failed"]}; skipped: {counts["skipped"]}. Runner exit: {result.returncode}.',
              '', 'Passing tests demonstrate the exercised behavior; they do not constitute formal protocol verification or production certification.']
    (directory/'security-tests.md').write_text('\n'.join(lines)+'\n')
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
