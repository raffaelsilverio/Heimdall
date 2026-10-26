#!/usr/bin/env python3
"""Prevent new oversized Go files and growth in the legacy size baseline."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "docs/quality/go_file_size_baseline.json"


def main() -> int:
    try:
        baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        max_lines = int(baseline_data["max_lines"])
        legacy = baseline_data["legacy_oversized"]
        if max_lines < 1 or not isinstance(legacy, dict):
            raise ValueError("invalid baseline format")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"could not read Go file-size baseline: {exc}", file=sys.stderr)
        return 2

    counts: dict[str, int] = {}
    failures: list[str] = []
    for path in sorted(ROOT.rglob("*.go")):
        if ".git" in path.parts or "vendor" in path.parts:
            continue
        relative = path.relative_to(ROOT).as_posix()
        try:
            counts[relative] = sum(1 for _ in path.open(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            failures.append(f"{relative}: cannot count lines: {exc}")

    for relative, line_count in counts.items():
        if line_count <= max_lines:
            continue
        limit = legacy.get(relative)
        if limit is None:
            failures.append(
                f"{relative}: {line_count} lines exceeds the {max_lines}-line limit; split the file or document a temporary baseline"
            )
        elif not isinstance(limit, int) or line_count > limit:
            failures.append(
                f"{relative}: {line_count} lines exceeds its legacy ceiling of {limit}; reduce the file or deliberately update the reviewed baseline"
            )

    for relative, limit in legacy.items():
        if relative not in counts:
            failures.append(f"stale size-baseline entry {relative}: remove it after deleting/renaming the file")
        elif counts[relative] <= max_lines:
            failures.append(f"{relative}: now below {max_lines} lines; remove its legacy size-baseline entry")
        elif counts[relative] > limit:
            # Already reported above with the file-specific ceiling.
            continue

    if failures:
        print("Go file-size quality gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    oversized = sum(1 for count in counts.values() if count > max_lines)
    print(f"Go file-size gate passed: no new oversized files; {oversized} legacy file(s) are at or below their reviewed ceilings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
