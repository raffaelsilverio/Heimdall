# Heimdall

Heimdall is a CLI harness for authorized offensive-security work. The current implementation includes saved programs, authorization/expiry checks, scope validation, a SQLite-backed scheduler, a passive OSINT tool catalog, and baseline/diff persistence.

## Build and test

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

The passive OSINT catalog includes Subfinder, Amass (forced passive mode), Uncover, and Gau. Opt-in DNS and web stages use AlterX/DNSx and HTTPx/TLSx. Tools run through direct argument arrays (never a generated shell command), with the current user's privileges. Use `heimdall tools list` and `heimdall tools doctor` to inspect integrations. Binary overrides use `HEIMDALL_<TOOL>` variables, for example `HEIMDALL_HTTPX` and `HEIMDALL_TLSX`.

By default, all four passive tools are enabled. `HEIMDALL_OSINT_TOOLS=subfinder,amass,gau` selects a subset for the daemon. Missing binaries are recorded and skipped; if a tool becomes available or its version changes, Heimdall starts a new baseline generation rather than treating the changed tool set as mass removals. A tool error makes that run incomplete, so it cannot advance the baseline. Uncover needs provider credentials in its own user config; Heimdall does not pass arbitrary environment secrets to child tools. Subfinder is invoked with its automatic update check disabled; Heimdall never updates these tools.

```sh
heimdall tools doctor
HEIMDALL_OSINT_TOOLS=subfinder,amass,gau heimdall daemon
```

## Data directory

By default, Heimdall stores `heimdall.db` under `os.UserConfigDir()/heimdall`. Override this with `HEIMDALL_HOME` or the global `--home` flag. The directory and database are restricted to the current user. SQLite is the operational source of truth.

## Programs and schedules

Create a program with an authorization reference, an RFC3339 expiry, and at least one included scope entry:

```sh
heimdall program add Acme \
  --authorization-ref 'https://example.test/program' \
  --expires-at '2027-01-01T00:00:00Z' \
  --wildcard-domain '*.example.com' \
  --port 80 --port 443 \
  --exclude-domain admin.example.com
```

Supported scope flags include `--domain`, `--wildcard-domain`, `--url`, `--ip`, and `--cidr`, with matching `--exclude-*` flags. Exact domains do not include subdomains; an explicit wildcard includes subdomains but not its root. Exclusions always take precedence. `--port` constrains included entries to those ports; without it, domain/IP/CIDR entries cannot be actively probed by the web stage. A URL entry authorizes its scheme, effective port, and path unless `--port` narrows it further.

New programs start as `draft`. Activation validates the stored scope and authorization and queues an initial OSINT run for the daemon:

```sh
heimdall program list
heimdall program show <program-id>
heimdall program activate <program-id>
heimdall daemon
```

### HackerOne source sync

For HackerOne programs, Heimdall reads the official Hacker API using Basic authentication. Create an API token in HackerOne API settings (available for Professional, Community, or Enterprise accounts), then set its username/identifier and value in the environment; credentials are never accepted as command-line arguments or stored in SQLite:

When creating the program, set `--platform hackerone --program-url 'https://hackerone.com/<handle>'`.

```sh
export HEIMDALL_HACKERONE_API_USERNAME='...'
export HEIMDALL_HACKERONE_API_TOKEN='...'
heimdall program source sync <program-id>
heimdall program source show <program-id>
heimdall program source show <program-id> --json
```

Sync reads the program, paginated structured scopes, and scope exclusions from `api.hackerone.com`, then stores a local snapshot and SHA-256 hash. A new or changed source creates a pending review; active programs are paused and cannot be activated while that review is pending. After inspecting the snapshot, explicitly choose one:

```sh
# Apply the representable HackerOne scope. Ports are not inferred from domain/IP/CIDR assets.
heimdall program source approve <program-id> --confirm-scope --port 443 --port 8443

# Or acknowledge the source but keep the existing local scope unchanged.
heimdall program source approve <program-id> --keep-current-scope

# Approval never resumes a program automatically.
heimdall program activate <program-id>
```

`--port` is an explicit local authorization decision, not a value imported from HackerOne; it applies only to included domain, wildcard, IP, and CIDR entries. URL assets retain their URL scheme/port. Assets the current scope model cannot represent (for example, mobile-app targets), an incomplete eligibility record, or HackerOne `open_scope` block applying the generated candidate; after review, `--keep-current-scope` resolves the pending review without changing local scope. HackerOne `scope_exclusions` describe excluded report categories, not excluded assets, so Heimdall stores them as policy metadata and does not convert them into scope exclusions. The API token must have access to the program; structured-scope pagination is rate-paced and bounded by HackerOne's documented 10,000-item pagination limit.

Endpoint reference: [HackerOne Hacker API](https://api.hackerone.com/hacker-resources/) and [authentication](https://api.hackerone.com/getting-started-hacker-api/).

The default OSINT schedule is daily at 03:00 in the detected IANA timezone (UTC if detection fails). Override it per program:

```sh
heimdall schedule set <program-id> --cron '0 4 * * *' --timezone America/Sao_Paulo
```

DNS is not scheduled by default. Explicitly enable it per authorized program:

```sh
heimdall schedule set <program-id> --stage dns --cron '0 5 * * 1' --timezone America/Sao_Paulo
```

The DNS stage filters AlterX candidates against the saved scope before sending them to DNSx, caps candidates at 5,000, and rate-limits DNSx to 10 requests/second. It records hostnames and DNS records; DNS record churn is non-material by default.

The web stage is also disabled until explicitly scheduled. It probes only in-scope URLs derived from authorized ports/URLs and the latest compatible OSINT/DNS hostname observations. Its defaults are 2 requests/second, concurrency 2, at most 1,000 targets, and a 10-minute stage timeout; override them per program:

```sh
heimdall schedule set <program-id> --stage web --cron '0 6 * * 1' \
  --timezone America/Sao_Paulo --rate-limit 2 --max-concurrency 2 --max-targets 1000 --timeout 600
```

HTTPx does not follow redirects or fall back to a different scheme. TLSx receives only authorized HTTPS targets. Pausing or expiring authorization cancels an in-progress stage; results are revalidated before they can advance the baseline.

Katana is an opt-in crawl stage seeded from the latest compatible web inventory. It disables redirects, headless mode, JavaScript crawling, and form filling; crawl and exclusion regexes are derived from the program scope. It uses a depth of 2, the stage rate/concurrency limits, and the same per-program target cap. Enable it separately:

```sh
heimdall schedule set <program-id> --stage crawl --cron '0 8 * * 1' \
  --timezone America/Sao_Paulo --rate-limit 2 --max-concurrency 2 --max-targets 1000 --timeout 600
```

FFUF and Nuclei are also opt-in stages. FFUF requires a user-managed wordlist via `HEIMDALL_FFUF_WORDLIST`; `max-targets` caps the total wordlist probes per run, and recursion/redirects are disabled. Nuclei requires a local, curated template directory via `HEIMDALL_NUCLEI_TEMPLATES`; Heimdall fingerprints it and runs only signed HTTP templates at info/low/medium severity, with redirects and Interactsh disabled.

```sh
heimdall schedule set <program-id> --stage ffuf --cron '0 9 * * 1' --timezone America/Sao_Paulo \
  --rate-limit 2 --max-concurrency 2 --max-targets 5000 --timeout 600
heimdall schedule set <program-id> --stage nuclei --cron '0 10 * * 1' --timezone America/Sao_Paulo \
  --rate-limit 2 --max-concurrency 2 --max-targets 100 --timeout 600
```

Nmap is an independent opt-in stage. It uses an unprivileged TCP connect scan (`-sT`), skips host discovery (`-Pn`), and scans only each target's explicitly authorized ports. It does not run version detection or NSE scripts. Defaults are one target at a time, a 5 probes/second cap, at most 256 targets, and a 20-minute stage timeout:

```sh
heimdall schedule set <program-id> --stage nmap --cron '0 7 * * 1' \
  --timezone America/Sao_Paulo --rate-limit 5 --max-concurrency 1 --max-targets 256 --timeout 1200
```

`heimdall daemon --once` runs one cycle and exits: at most one due recon job plus a bounded batch of pending event triage tasks. The regular daemon checks every 30 seconds, coalesces missed occurrences to one catch-up run, and runs recon jobs sequentially. When authorization expires, the program is paused and its schedules are disabled. Paused or draft programs do not run.

## Recon baseline and changes

The first complete OSINT run creates a baseline without emitting a change event. Later complete runs emit material events for new hostnames. A hostname is marked removed only after it is absent from two consecutive complete runs; failed and partial runs do not advance the baseline. Scope and profile revisions are part of the baseline key.

Sanitized per-tool artifacts are stored under the Heimdall data directory with SHA-256 metadata. List artifacts for a run with `heimdall artifacts <run-id>`; out-of-scope results are filtered and query strings are removed from archived URLs before persistence.

Inspect persisted events with:

```sh
heimdall changes list [program-id]
```

## Sessions

Interactive sessions are separate from programs and recon runs. The TUI/REPL is not implemented yet; for now, resume a persisted conversation by passing its session ID to `run`:

```sh
heimdall session create <program-id> --title 'Acme triage'
heimdall run --session <session-id> --prompt 'Summarize the current attack surface'
heimdall session show <session-id>
heimdall session list <program-id>
```

The CLI sends the most recent 100 stored user/assistant messages to the selected provider and stores each turn locally. Material recon changes also create a separate `agent_event` session and a pending task in the same SQLite transaction. Event triage below is deterministic; the proposal-only planner does not execute tools, and the autonomous tool-execution worker is not implemented.

Material change tasks now have a deterministic, read-only triage stage. The daemon processes them automatically; it writes a structured handoff to per-program memory and the event session, but makes no LLM calls and executes no recon. To run one bounded batch manually:

```sh
heimdall agent triage --limit 10
heimdall agent tasks <program-id>
```

The original `agent_tasks` row remains pending for the later planner/worker stage; deterministic preparation has its own `agent_event_triage_jobs` queue and lifecycle. Lease, attempt count, handoff memory, and session message are committed together so expired workers can be retried without duplicate handoffs. Failed deterministic triage can be requeued explicitly with `heimdall agent retry-triage <program-id> <task-id>`.

Agent action policy is saved per program and defaults to deny-all. Configure a profile explicitly:

```sh
heimdall program policy show <program-id>
heimdall program policy set <program-id> \
  --allow-stage web --allow-class safe_active \
  --max-actions-per-run 2 --max-requests-per-run 100 \
  --max-requests-per-action 20 --max-targets-per-action 10
heimdall program policy reset <program-id>
```

`heimdall agent plan <program-id>` reads a JSON proposal from stdin and checks it against the program policy, active schedule, current authorization, source-review state and scope/port rules. It is a dry-run: no LLM calls, scans or tools are run, and the result reports `execution_available: false`.

An opt-in model can draft those proposals with `heimdall agent propose <program-id> --send-context`. This sends the program's structured scope and policy to the configured provider, but not memory notes, raw HTTP traffic, or artifacts. Memory is a separate opt-in: add `--include-memory` to send up to eight active, unexpired notes from that same program (at most 8 KiB), excluding stale scope/source records and any notes while source review is pending. Without both flags, memory is not read into the model context. Review notes before sending because they may contain sensitive content. The generated JSON still passes through the same policy validator; it cannot invoke tools. Without `--send-context`, the command refuses to send program data. The budget is checked per proposed plan; a persistent action-budget ledger and executor are still future work.

```sh
heimdall agent propose <program-id> --send-context --include-memory
```

### Program-scoped memory (first increment)

Memory records are explicitly attached to one program. Search, listing, retrieval, provenance references, and supersession all require the same `program-id`; there is no global memory search. Source references to runs, events, sessions, snapshots, and artifacts are checked against that program. Records preserve scope/source hashes, can be superseded without deleting history, and can expire or be archived.

```sh
heimdall memory add <program-id> --kind hypothesis \
  --title 'Login redirect behavior' \
  --content 'The login endpoint redirected during the first test; verify with a fresh session.' \
  --source-kind run --source-id <run-id> --confidence 0.6

heimdall memory search <program-id> 'login redirect'
heimdall memory list <program-id>
heimdall memory show <program-id> <memory-id>
heimdall memory archive <program-id> <memory-id>
heimdall memory restore <program-id> <memory-id>
```

Use `--content-stdin` instead of `--content` for sensitive notes so their body does not appear in shell history. This increment is local SQLite/FTS only: no vector store or automatic LLM call. Notes are never injected into `run`; `agent propose` can include a bounded, freshness-filtered briefing only with the explicit `--send-context --include-memory` opt-ins. Memory is advisory and never grants authorization. Older scope/source provenance is flagged when displayed or searched and excluded from planner context.

## Current scope

Amass, Uncover, Gau, AlterX, DNSx, HTTPx, TLSx, Nmap, Katana, FFUF, and Nuclei are integrated. OSINT tool selection and the FFUF wordlist/Nuclei template paths are currently configured through environment variables; schedules, ports, limits and deny-by-default agent policy are stored per program. The deterministic event-triage worker is active, but the LLM planner and tool-execution worker remain future work. Active stages require per-program scope, schedule, limits, and valid authorization; change events create handoffs but do not launch scans or an agent yet.
