#!/usr/bin/env python3
"""Run race-enabled Go tests and ratchet coverage on critical packages."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/raffaelsilverio/Heimdall"
THRESHOLDS_PATH = ROOT / "docs/quality/coverage_thresholds.json"


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def main() -> int:
    try:
        thresholds = json.loads(THRESHOLDS_PATH.read_text(encoding="utf-8"))["packages"]
        if not isinstance(thresholds, dict) or not thresholds:
            raise ValueError("coverage package thresholds must be a non-empty object")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"could not read package coverage thresholds: {exc}", file=sys.stderr)
        return 2

    packages_result = run(["go", "list", "-f", "{{.ImportPath}}", "./..."])
    if packages_result.returncode:
        print(packages_result.stdout, end="")
        print(packages_result.stderr, file=sys.stderr, end="")
        return packages_result.returncode
    import_paths = sorted(packages_result.stdout.splitlines(), key=len, reverse=True)

    with tempfile.TemporaryDirectory(prefix="heimdall-cover-") as directory:
        profile = Path(directory) / "coverage.out"
        tests = run(["go", "test", "-race", "-count=1", f"-coverprofile={profile}", "./..."])
        print(tests.stdout, end="")
        print(tests.stderr, file=sys.stderr, end="")
        if tests.returncode:
            return tests.returncode
        if not profile.is_file():
            print("go test did not produce a coverage profile", file=sys.stderr)
            return 2

        totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for line in profile.read_text(encoding="utf-8").splitlines():
            if line.startswith("mode:") or not line:
                continue
            try:
                source, statement_count, execution_count = line.rsplit(" ", 2)
                filename = source.split(":", 1)[0]
                statements = int(statement_count)
                executed = int(execution_count) > 0
            except (ValueError, IndexError):
                print(f"invalid Go coverage profile line: {line}", file=sys.stderr)
                return 2

            package = next(
                (path for path in import_paths if filename == path or filename.startswith(path + "/")),
                None,
            )
            if package is None or not package.startswith(MODULE):
                continue
            relative = package.removeprefix(MODULE + "/")
            totals[relative][0] += statements
            if executed:
                totals[relative][1] += statements

    failures: list[str] = []
    for package, minimum in sorted(thresholds.items()):
        if not isinstance(minimum, (int, float)) or minimum < 0 or minimum > 100:
            failures.append(f"invalid threshold for {package}: {minimum!r}")
            continue
        statements, covered = totals.get(package, [0, 0])
        if statements == 0:
            failures.append(f"{package}: no executable statements were covered; test package mapping is missing")
            continue
        percentage = 100.0 * covered / statements
        print(f"coverage {package}: {percentage:.1f}% (minimum {minimum:.1f}%)")
        if percentage + 1e-9 < minimum:
            failures.append(f"{package}: {percentage:.1f}% is below the required {minimum:.1f}%")

    if failures:
        print("Critical-package test coverage gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Race-enabled tests passed and critical-package coverage floors were met.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
