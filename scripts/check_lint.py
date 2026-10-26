#!/usr/bin/env python3
"""Run pinned golangci-lint and enforce a reviewed per-file debt ratchet."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "docs/quality/lint_baseline.json"
COMPLEXITY_PATTERNS = {
    "gocyclo": re.compile(r"cyclomatic complexity (\d+) of func `([^`]+)`"),
    "gocognit": re.compile(r"cognitive complexity (\d+) of func `([^`]+)`"),
}


def collect_report() -> tuple[dict, int]:
    command = [
        "go", "run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0",
        "run", "--output.json.path=stdout", "--show-stats=false", "--issues-exit-code=0",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode:
        print(f"golangci-lint failed to run (exit {result.returncode})", file=sys.stderr)
        return {}, result.returncode
    try:
        return json.loads(result.stdout or "{}"), 0
    except json.JSONDecodeError as exc:
        print(f"golangci-lint returned invalid JSON: {exc}", file=sys.stderr)
        return {}, 2


def summarize(report: dict) -> tuple[Counter, dict, Counter]:
    counts: Counter = Counter()
    ceilings: dict[str, dict[str, dict[str, int]]] = {
        name: defaultdict(dict) for name in COMPLEXITY_PATTERNS
    }
    totals: Counter = Counter()
    issues = report.get("Issues") or []
    for issue in issues:
        linter = issue.get("FromLinter", "unknown")
        path = Path(issue.get("Pos", {}).get("Filename", "unknown")).as_posix()
        counts[(linter, path)] += 1
        totals[linter] += 1
        pattern = COMPLEXITY_PATTERNS.get(linter)
        if pattern:
            match = pattern.search(issue.get("Text", ""))
            if match:
                function = match.group(2)
                ceilings[linter][path][function] = max(
                    ceilings[linter][path].get(function, 0), int(match.group(1))
                )
    return counts, ceilings, totals


def encode_baseline(report: dict, rationale: str) -> dict:
    counts, ceilings, totals = summarize(report)
    by_linter: dict[str, dict[str, int]] = defaultdict(dict)
    for (linter, path), count in sorted(counts.items()):
        by_linter[linter][path] = count
    return {
        "schema_version": 1,
        "rationale": rationale,
        "known_issue_totals": dict(sorted(totals.items())),
        "max_issues_per_file": {key: dict(sorted(value.items())) for key, value in sorted(by_linter.items())},
        "complexity_ceilings_by_function": {
            key: {
                path: dict(sorted(functions.items()))
                for path, functions in sorted(value.items())
            }
            for key, value in sorted(ceilings.items())
        },
    }


def check_report(report: dict, baseline: dict) -> int:
    try:
        if baseline.get("schema_version") != 1:
            raise ValueError("unsupported lint baseline schema")
        known = baseline["max_issues_per_file"]
        complexity = baseline["complexity_ceilings_by_function"]
        if not isinstance(known, dict) or not isinstance(complexity, dict):
            raise ValueError("invalid lint baseline mappings")
    except (KeyError, TypeError, ValueError) as exc:
        print(f"invalid lint baseline: {exc}", file=sys.stderr)
        return 2

    counts, ceilings, totals = summarize(report)
    failures: list[str] = []
    for (linter, path), count in sorted(counts.items()):
        allowed = known.get(linter, {}).get(path, 0)
        if count > allowed:
            failures.append(f"{linter} in {path}: {count} finding(s), reviewed ceiling is {allowed}")

    for linter, paths in ceilings.items():
        allowed_paths = complexity.get(linter, {})
        for path, functions in sorted(paths.items()):
            for function, value in sorted(functions.items()):
                allowed = allowed_paths.get(path, {}).get(function, 0)
                if value > allowed:
                    failures.append(
                        f"{linter} in {path} ({function}): complexity {value} exceeds reviewed ceiling {allowed}"
                    )

    if failures:
        print("Lint debt ratchet failed; fix new findings or reduce the reviewed baseline:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    current_total = sum(totals.values())
    allowed_total = sum(baseline.get("known_issue_totals", {}).values())
    print(f"Lint debt ratchet passed: {current_total} known finding(s), no per-file or per-function complexity regression (baseline {allowed_total}).")
    if current_total < allowed_total:
        print("Lint findings were reduced; update the reviewed baseline to ratchet down the remaining allowance.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true", help="write a new baseline; requires --reason")
    parser.add_argument("--reason", help="review rationale for an explicit baseline update")
    arguments = parser.parse_args()

    if arguments.update_baseline and not arguments.reason:
        parser.error("--update-baseline requires a non-empty --reason")
    if arguments.reason and not arguments.update_baseline:
        parser.error("--reason is only valid with --update-baseline")

    report, error = collect_report()
    if error:
        return error
    if arguments.update_baseline:
        BASELINE_PATH.write_text(
            json.dumps(encode_baseline(report, arguments.reason.strip()), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Updated reviewed lint baseline: {BASELINE_PATH.relative_to(ROOT)}")
        return 0

    try:
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read lint baseline: {exc}", file=sys.stderr)
        return 2
    return check_report(report, baseline)


if __name__ == "__main__":
    raise SystemExit(main())
