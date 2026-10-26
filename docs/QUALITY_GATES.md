# Quality gates and code-health policy

The project has no deployable service yet, so its immediate CI/CD gate is a
reproducible validation pipeline. A release/deployment workflow should be
added when the CLI distribution target and signing/release process are chosen;
it must depend on the same quality gate rather than duplicate or bypass it.

## Required checks

Run the same checks locally and in GitHub Actions with:

```sh
make check
```

The target fails on:

- Go files that are not `gofmt`-formatted;
- `go.mod`/`go.sum` drift (`go mod tidy -diff`);
- violations of package dependency boundaries (`scripts/check_architecture.py`);
- new Go files above 500 lines or growth beyond the reviewed legacy size ceilings;
- duplication, cyclomatic/cognitive complexity, long functions, unchecked errors,
  security patterns (`gosec`), `go vet`, or Staticcheck findings (pinned tools);
- known vulnerabilities detected by pinned `govulncheck`;
- fresh race-enabled test failures and critical-package coverage drops
  (`scripts/check_test_quality.py` runs `-count=1`);
- build failures.

Pull requests and pushes to the primary branch must pass this workflow. Keep
workflow permissions read-only unless a specific job requires more. Do not put
live model credentials, authorized targets, or external recon in CI; security
tests must use fixtures, fake providers, and loopback servers.

## Architecture and review rules

- Preserve bounded package responsibilities: `cmd` handles CLI/wiring;
  `assessment` owns scope/authorization domain rules; `agent` owns planner and
  agent contracts; `recon` owns registered adapters; `scheduler` owns job
  orchestration; `store` owns SQLite transactions and persistence.
- Keep `assessment` independent of application/adapters; keep `recon` and
  `agent/contract` dependent only on assessment among Heimdall packages; keep
  `providers` independent of internal packages. The CLI/composition root is
  the only layer that may import `cmd`.
- Keep authorization, scope, consent, policy and request accounting in the
  trusted Go path. Models and external-tool output are untrusted inputs.
- Add capabilities through typed, registered adapters. No generated shell,
  subprocess, implicit network access, or cross-program/workspace memory.
- Keep persistence transactions and network/tool calls separated. Do not hold
  database transactions open while calling a provider or target.
- Add tests for behavior at package boundaries, failure/cancellation paths,
  migrations, scope isolation and request-budget enforcement. No test may make
  a real external request.
- Prefer small cohesive files and functions. New Go files must stay at or below
  500 lines. Existing larger files are temporary debt and may not grow without
  a reviewed baseline change. The baseline is not a design target.
- Migrations are append-only; changes to consent, permission or request caps
  require tests showing old consent fails closed and must not silently acquire
  broader permissions.

## Existing size debt and refactor order

Current over-limit files are tracked in
[`go_file_size_baseline.json`](quality/go_file_size_baseline.json). Split them
incrementally, preserving exported APIs and adding characterization tests
before moving behavior. Suggested order:

1. `internal/store/agent_action_ledger.go` — run lifecycle, reservations,
   request accounting, and operator review into cohesive files.
2. `internal/agent/execution/executor.go` — separate planning loop, action
   dispatch, and current-state/consent validation.
3. `internal/store/agent_cycle_jobs.go` — queue leasing, job review, and list/
   serialization concerns.
4. `internal/store/memory.go`, `internal/store/runs.go`,
   `internal/assessment/program.go`, and `internal/store/store_test.go` by
   responsibility or test fixture.

After a file falls below 500 lines, remove its baseline entry in the same PR.
Do not split files mechanically just to hit a number: each resulting file must
own one cohesive responsibility and keep dependencies flowing through clear
interfaces.

## Raising the bar gradually

Coverage floors are package-specific, start slightly below today's measurements,
and should be raised as security-path tests improve; coverage is a minimum bar,
not proof of good assertions. Tests must verify behavior and failure paths, not
merely execute lines. Duplication and error-handling linters cover tests too;
complexity/length signals are focused on production code so Arrange/Act/Assert
tests are not penalized for explicit setup and checks.
The current linter baseline is a temporary ratchet, scoped by linter and file;
cyclomatic/cognitive ceilings are tracked per function. New findings, growth in
a file's finding count, or increased per-function complexity fail CI. Use
`python3 scripts/check_lint.py --update-baseline --reason '...'` only when a
reviewed refactor removes findings or when an explicitly approved finding is
added. Baseline changes require review and must not be used to normalize new
debt. Continue shrinking the baseline until the lint run is clean; never disable
a linter project-wide to make CI green.

The initial baseline is **not clean**: it records 146 inherited findings
(5 duplication, 54 unchecked-error, 52 cognitive-complexity, 18 cyclomatic-
complexity, 13 gosec, and 4 additional Staticcheck findings). This is visible
debt, not a quality target. Before expanding product features, reduce it in
priority order: review all gosec findings; split high-complexity executor/store
operations; remove duplicated CLI handlers; then resolve unchecked-error and
Staticcheck findings. Every cleanup should lower the baseline, and no exception
should silently broaden authorization, filesystem or network behavior.
