#!/usr/bin/env python3
"""Enforce a small set of explicit Go package dependency boundaries."""

from __future__ import annotations

import subprocess
import sys


MODULE = "github.com/raffaelsilverio/Heimdall"


def main() -> int:
    command = ["go", "list", "-f", '{{.ImportPath}} {{join .Imports " "}}', "./..."]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        print(result.stderr, file=sys.stderr, end="")
        return result.returncode

    violations: list[str] = []
    for line in result.stdout.splitlines():
        importer, _, imports = line.partition(" ")
        imported = imports.split()
        internal_imports = [item for item in imported if item.startswith(f"{MODULE}/internal/")]

        if importer not in {f"{MODULE}/cmd", MODULE} and f"{MODULE}/cmd" in imported:
            violations.append(f"{importer} imports the CLI composition root {MODULE}/cmd")

        if importer == f"{MODULE}/internal/assessment" and internal_imports:
            violations.append(f"{importer} is a domain package and must not import application/adapter packages: {internal_imports}")

        if importer == f"{MODULE}/providers" and internal_imports:
            violations.append(f"{importer} is a provider boundary and must not depend on Heimdall internals: {internal_imports}")

        if importer in {f"{MODULE}/internal/recon", f"{MODULE}/internal/agent/contract"}:
            allowed = {f"{MODULE}/internal/assessment"}
            forbidden = [item for item in internal_imports if item not in allowed]
            if forbidden:
                violations.append(f"{importer} may depend on assessment, not higher-level packages: {forbidden}")

    if violations:
        print("Go architecture boundary check failed:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print("Go architecture boundaries passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
