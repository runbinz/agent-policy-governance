#!/usr/bin/env python3
"""Audit locked dependencies; fail on new findings and any active affected package."""
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# SQLx0.8's optional backends appear in Cargo.lock but are absent from the
# enabled PostgreSQL feature graph. An enabled backend makes these fatal too.
INACTIVE_ONLY = {
    ('RUSTSEC-2023-0071', 'rsa'): 'SQLx optional MySQL backend; PostgreSQL only',
    ('RUSTSEC-2026-0459', 'libsqlite3-sys'): 'SQLx optional SQLite backend; PostgreSQL only',
}


def assess(report, active):
    failures = []
    notices = []
    findings = list(report['vulnerabilities']['list'])
    for entries in report.get('warnings', {}).values():
        findings.extend(entries)
    for item in findings:
        package = item['package']
        advisory = item['advisory']
        key = (advisory['id'], package['name'])
        label = f"{advisory['id']} {package['name']} {package['version']}"
        if (package['name'], package['version']) in active or key not in INACTIVE_ONLY:
            failures.append(label)
        else:
            notices.append(f"Inactive lockfile exception: {label}: {INACTIVE_ONLY[key]}")
    return failures, notices


def run(args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"{args[0]} failed (exit {result.returncode})")
    return result


def main():
    # cargo tree resolves enabled normal/build/dev dependencies for this target.
    tree = run(['cargo', 'tree', '--locked', '--workspace', '--edges', 'normal,build,dev',
                '--prefix', 'none', '--format', '{p}'])
    if tree.returncode:
        raise RuntimeError('cannot resolve active Cargo dependency graph')
    active = set(re.findall(r'^([\w-]+) v([^\s]+)', tree.stdout, re.MULTILINE))
    if not active:
        raise RuntimeError('empty Cargo dependency graph')
    audit = run(shlex.split(os.environ.get('CARGO_AUDIT', 'cargo audit')) + ['--json'])
    report = json.loads(audit.stdout)
    # A tool error must never be mistaken for an empty vulnerability list.
    if 'list' not in report.get('vulnerabilities', {}):
        raise RuntimeError('invalid Cargo audit report')
    failures, notices = assess(report, active)
    for notice in notices:
        print(notice)
    for failure in failures:
        print('Rust advisory: ' + failure)
    if audit.returncode and not (failures or notices):
        raise RuntimeError('Cargo audit failed without an explained advisory')
    npm = run(['npm', 'audit', '--json'], ROOT / 'apps/console')
    npm_report = json.loads(npm.stdout)
    if 'error' in npm_report or 'vulnerabilities' not in npm_report.get('metadata', {}):
        raise RuntimeError('invalid npm audit report')
    count = npm_report['metadata']['vulnerabilities'].get('total')
    if not isinstance(count, int):
        raise RuntimeError('missing npm advisory count')
    print(f'npm advisories: {count}')
    if npm.returncode and count == 0:
        raise RuntimeError('npm audit failed without an explained advisory')
    if failures or count:
        return 1
    print('Dependency gate passed for enabled features on this target.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        print(f'Dependency gate failed: {error}', file=sys.stderr)
        sys.exit(1)
