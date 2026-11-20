# Heimdall

Heimdall is a CLI harness for authorized offensive-security work. The current implementation includes saved programs, authorization/expiry checks, scope validation, a SQLite-backed scheduler, a passive OSINT tool catalog, and baseline/diff persistence.

See the [development roadmap](Development-roadmap.md) and the [current implementation status and gates](roadmap/21-estado-atual-e-gates.md) for the current state, security boundaries and acceptance criteria. The Workspace/Code mode is described in [roadmap/22-workspace-code-mode.md](roadmap/22-workspace-code-mode.md), and deployment/operations in [roadmap/23-operacao-e-deploy.md](roadmap/23-operacao-e-deploy.md).

## Build and test

The required local/CI quality gate is:

```sh
make check
```

It checks formatting, module tidiness, package boundaries, Go file-size limits,
`go vet`, complexity/duplication/error-handling linters, Staticcheck,
`govulncheck`, race-enabled tests with critical-package coverage floors, and
buildability. See
[docs/QUALITY_GATES.md](docs/QUALITY_GATES.md) for architecture conventions,
the legacy large-file baseline, and the staged refactoring policy.

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

## Configuration

Runtime settings resolve with the precedence **flag > environment > config file > defaults**. Unless `--config` points elsewhere, Heimdall loads `<home>/config.yaml` when it exists; an explicitly selected file must exist, and a malformed or invalid configuration aborts the command.

```yaml
provider: opencode
model: <model-id>
log_level: info
log_format: json
request_timeout: 60s
context_max_bytes: 262144
```

`provider` must be `openai` or `opencode`, `log_level` one of `debug`, `info`, `warn` or `error`, `log_format` one of `text` or `json`, `request_timeout` a Go duration between `1s` and `10m`, and `context_max_bytes` between `16384` and `1048576`. The equivalent flags are `--log-level`, `--log-format`, `--request-timeout` and `--context-max-bytes`; environment overrides are `HEIMDALL_PROVIDER`, `HEIMDALL_MODEL`, `HEIMDALL_LOG_LEVEL`, `HEIMDALL_LOG_FORMAT`, `HEIMDALL_REQUEST_TIMEOUT` and `HEIMDALL_CONTEXT_MAX_BYTES`. API keys are never read from the config file: `openai` uses `OPENAI_API_KEY` and `opencode` uses `OPENCODE_API_KEY`. The daemon and scheduler emit structured `slog` records using the same level and format.

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

The CLI sends at most the most recent 100 stored user/assistant messages, after trimming the oldest turns to fit `context_max_bytes`; system messages and the newest prompt are never dropped. When turns are omitted, one explicit system marker replaces them, a `slog` record reports the dropped counts, and the assistant message metadata records the context and dropped byte counts for audit. A bounded current-memory briefing can be added only with `heimdall run --session <session-id> --include-memory --prompt '...'`; the session pins one program and the command rejects a stale session scope. The briefing is filtered to that program, excludes stale or source-review-pending records, is advisory/untrusted, and its selected memory IDs and scope hash are recorded as user-message metadata. Material recon changes also create a separate `agent_event` session and a pending task in the same SQLite transaction. Event triage below is deterministic; the proposal-only planner does not execute tools, and the autonomous tool-execution worker is not implemented.

Material change tasks now have a deterministic, read-only triage stage. The daemon processes them automatically; it writes a structured handoff to per-program memory and the event session, but makes no LLM calls and executes no recon. The handoff may include up to five bounded notes from the same program, only when the event scope still matches the current scope and no source review is pending; stale-scope and stale-source notes are excluded. The memory snapshot is revalidated at commit, so a changed briefing causes a retry instead of persisting stale context. To run one bounded batch manually:

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

Outbound HTTP requests use a separate per-program request profile. It is applied by one middleware to native HTTP probes and to every stage that sends HTTP (web, crawl, fuzzing and Nuclei); the TLS handshake sends no HTTP headers:

```sh
heimdall program request-profile show <program-id>
heimdall program request-profile set <program-id> \
  --user-agent 'Heimdall/1.0 (security research)' \
  --header 'X-Bug-Bounty=researcher-one'
heimdall program request-profile reset <program-id>
```

The profile always has a non-empty User-Agent and at most 16 headers. Names are canonicalized and sorted; duplicates, empty values, CR/LF, non-printable bytes, oversized values and framing/credential headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Authorization`, `Cookie`, `User-Agent`, etc.) are rejected before any request. Each change increments an auditable revision; the executor stores that revision with the action result, and header values are never written to logs or observations. Test-account credentials are intentionally outside this mechanism.

`heimdall agent plan <program-id>` reads a JSON proposal from stdin — either a flat `actions` list or a `tasks` graph with `depends_on` — and checks it against the program policy, active schedule, current authorization, source-review state and scope/port rules. Task ids must be unique, dependencies must exist and must not form a cycle; actions are flattened into deterministic dependency order and the validated task summaries are reported next to the policy decisions. It is a dry-run: no LLM calls, scans or tools are run, and the result reports `execution_available: false`.

`heimdall agent tools [--json]` lists the compiled agent catalog and its reviewed argument schemas without opening the database or sending any request. Each entry declares its version, stage, risk class, origin, isolation profile, target types, scope rule, target/request caps and accounting; only compiled `safe_active` adapters with `native_in_process_metered`, `one_request_per_target` and `program_active_url` are marked autonomous. The catalog is static: only adapters compiled into the binary can run, and the registry rejects unknown ids, invalid metadata, wrong stages, empty or oversized targets, and request budgets that do not cover every target before dispatch.

Native function calling is opt-in. `heimdall agent propose <program-id> --send-context --tools` advertises only the compiled tools that match the program's current stage/class allowlist, using the reviewed argument schemas. The provider may return text or `function_call` items; every call is revalidated against the registry and schema, and each accepted call becomes one policy-checked action proposal with the program scope hash and one metered request per target. Undeclared tools, repeated call ids, malformed or unknown arguments, and calls above the remaining response limit are rejected. This command still only proposes: it never executes a tool.

The execution foundation has a durable per-program action-run ledger (`012_agent_action_ledger.sql` through `023_agent_cycle_job_review.sql`; migrations add request usage, result storage, operator review, planner egress audit, consented cycle queue/daily caps, memory-ID audit, automation-bound action snapshots, a daily request ceiling, policy-revision binding and cycle-job review metadata). These migrations reset older persistent automation consent so it must be re-approved with current limits/policy. The ledger snapshots authorization, scope and policy revision; reservations are idempotent, consume action/request budget atomically, validate registered stage/class, schedule limits and serialized targets against current scope, then require a just-in-time recheck before transitioning to `running`. `ConsumeAgentActionRequest` charges each native outbound attempt before sending it and rechecks the current authorization, scope, policy and (for daemon cycles) automation consent; retries count separately. `recon.MeteredRoundTripper` fails closed without this meter, and `scheduler.AgentActionRequestMeter` adapts it to the persistent ledger. The compiled agent adapters are `native_http_probe` and `native_tls_probe`. The HTTP probe sends one in-scope `HEAD` per target, with no redirect following, no request body, and no response-body persistence. The TLS probe performs one in-scope HTTPS handshake per target and records only bounded certificate metadata, without an HTTP request or body. Both refuse to start unless the reserved request budget covers every target, and the executor selects the adapter from the proposal's `tool` field after validating it against the registry. The executor and the daemon load the program request profile before dispatch, so every outbound HTTP request carries the reviewed User-Agent and mandatory headers; an invalid profile fails closed. The `agent plan` and `agent propose` dry-runs apply the same registry/schema validation and expose no grants for unknown tools. Expired action or cycle leases become uncertain/review-required and are never automatically replayed. The daemon claims only future material-event jobs created while persistent consent is enabled; external subprocess tools bypass the Go HTTP meter and remain unavailable to the agent. A controlled subprocess core (`AgentExecSpec`/`AgentExecRunner`) exists for reviewed Go/Python/Shell tools: clean absolute binary, exact argv allowlist, no shell or `-c` command strings, sanitized environment with `HOME`/`TMPDIR` in an ephemeral directory, capped stdin/stdout/stderr, timeout, process-group termination and typed exit errors. A reviewed sandbox is mandatory: on macOS `sandbox-exec` denies network access and writes outside the ephemeral directory; on Linux `bubblewrap --unshare-net` is used when available; otherwise the runner fails closed with `ErrAgentExecSandboxUnavailable` before starting the process. It is not registered in the agent catalog, so no subprocess can run in a cycle until request accounting and a catalog-level target schema are implemented. The admission model, required evidence and the future `subprocess_metered_proxy` profile are defined in `roadmap/24-isolamento-e-accounting-de-subprocessos.md`; `AgentToolSpec.Validate` rejects any isolation profile other than `native_in_process_metered`.

To execute a manually reviewed plan, configure an explicit per-program `web` policy and pass up to 20 actions as JSON to the native-only command. The whole plan is policy-checked before the first request; execution stops on the first failed action and does not ask a model to invent follow-ups:

```sh
heimdall agent execute <program-id> \
  --action-run-id <new-uuid> --confirm-active-requests <<'JSON'
{"actions":[{"stage":"web","scope_hash":"<current-scope-hash>","targets":["https://app.example.test/health"],"estimated_calls":1,"rationale":"Single bounded HEAD probe"}]}
JSON
```

The same input may instead be a task graph: `{"tasks":[{"id":"discover","objective":"...","actions":[...]},{"id":"probe","objective":"...","depends_on":["discover"],"actions":[...]}]}`. Dependencies run first, ready tasks keep their original order, and `actions` and `tasks` cannot be combined. This sends an active `HEAD` request for each authorized target. It requires a fresh unique action-run UUID; reusing a completed run ID does not replay it. The command accepts 1–20 `web` actions in sequence and has no shell/subprocess path. Do not run it against real targets unless the program authorization and configured policy explicitly permit this test.

For a bounded adaptive cycle, `agent cycle` asks the model for one next action at a time, feeds back only prior probe target/status summaries, and executes each accepted action under the same ledger and run budgets:

```sh
heimdall agent cycle <program-id> \
  --action-run-id <new-uuid> --model <model> \
  --send-context --confirm-active-requests --max-steps 3
```

`--send-context` consents to sending structured scope, policy, and bounded probe results to the model. `--include-memory` is a further opt-in for up to eight fresh notes from this program only. Provider/model, planner-call count, and the IDs of memory notes sent are recorded in the action-run ledger. The manual cycle is capped at 20 steps and by policy budgets; it stops when the model proposes no action, repeats a target, reaches budget, or an action fails. The daemon runs only future event cycles with persistent consent. Both paths can dispatch only the native HEAD probe; no shell or subprocess adapters are registered. Native model tool calling is available only in `agent propose --tools`; the synchronous and daemon cycle planners still use the bounded JSON action/task contract.

`SIGINT` and `SIGTERM` cancel the running command. In-flight action runs and cycle jobs are closed as `failed` through a short persistence window that is not cancelled, so an interrupted command does not leave an active run behind.

Persistent consent for a future background cycle is separate and deny-by-default. Configure it only after setting the program's action policy:

```sh
heimdall program automation set <program-id> \
  --provider openai --model <model> \
  --context-egress-expires-at <RFC3339-time-within-90-days> \
  --allow-model-context-egress --allow-active-requests \
  --max-cycles-per-day 2 --max-requests-per-day 100 \
  --max-steps-per-cycle 2 \
  --reviewed-by <operator> --reason 'Approved bounded adaptive HEAD checks'
heimdall program automation show <program-id>
heimdall program automation disable <program-id> \
  --reviewed-by <operator> --reason 'Revoked by program owner'
```

`program automation set` records provider/model, separate egress/request consent, expiry, cycle/step caps and a daily request cap; `--include-memory` is an additional explicit consent. `show` includes today's cycles and request units reserved. It does not immediately start a cycle or backfill old tasks. **Future material-event tasks** created while the consent is enabled are added to the durable adaptive-cycle queue; the daemon claims them only while the current consent, authorization, policy revision, web schedule, and source-review gates remain valid. Cycle and daily request budgets are atomically reserved at claim; unused reserved requests are not refunded. Failed/expired jobs are not retried automatically. Migrations that add consent limits or policy binding disable prior automation consents, so review and re-enable them explicitly. Inspect queue state with `heimdall agent cycle-jobs <program-id>`; close a `needs_review` queue job with `agent cycle-review <program-id> <task-id> --decision assessed_no_action|assessed_failed|assessed_completed --reviewed-by <operator> --note '<rationale>'`. If its action run has uncertain actions, review those first with `agent action-review`.

Inspect durable outcomes (including an `uncertain` status after a crash) with:

```sh
heimdall agent action-runs <program-id>
heimdall agent action-run <program-id> <action-run-id>
heimdall agent action-review <program-id> <action-run-id> <action-id> \
  --decision assessed_not_executed --reviewed-by <operator> \
  --note 'Reviewed executor and target logs; no request was observed.'
```

Each stored action result includes a normalized `profile_version`, one `outcomes` entry per authorized target (method, status code, result), and bounded `logs` covering start, each request completion, failures, and finish. These records never contain response headers, response bodies, request bodies, or credentials. The logs are adapter events, not subprocess stdout/stderr; the only executable adapter remains the native HEAD probe.

Review records are append-once and require an operator plus a rationale. The action retains status `uncertain`, its request budget remains consumed, and review never retries it. When every uncertain action in a run has an assessment, the run closes as `failed`; start a new, explicitly authorized action run if further testing is warranted.

An opt-in model can draft proposals without executing them with `heimdall agent propose <program-id> --send-context`. The model may return a flat action list or a bounded task graph with `depends_on`; the same validator checks task ids, dependencies, cycles, scope and policy, then reports the dependency-ordered actions and task summaries. Add `--tools` to advertise the compiled tools that match the current policy allowlist for native function calling; returned calls are revalidated locally and converted into the same action proposals (native calls form a flat list, while task graphs remain text-mode). This sends the program's structured scope and policy to the configured provider, but not memory notes, raw HTTP traffic, or artifacts. Memory is a separate opt-in: add `--include-memory` to send up to eight active, unexpired notes from that same program (at most 8 KiB), excluding stale scope/source records and any notes while source review is pending. Without both flags, memory is not read into the model context. Review notes before sending because they may contain sensitive content. The generated JSON still passes through the same policy validator; this command never executes tools. Without `--send-context`, the command refuses to send program data. The synchronous `agent cycle` executor is separate and requires its own planner-egress and active-request confirmations.

```sh
heimdall agent propose <program-id> --send-context --include-memory
heimdall agent propose <program-id> --send-context --tools
```

### Program-scoped memory (first increment)

Memory records are explicitly attached to one program. Search, listing, retrieval, provenance references, and supersession all require the same `program-id`; there is no global memory search. Source references to runs, events, sessions, snapshots, and artifacts are checked against that program. Records preserve scope/source hashes, can be superseded without deleting history, and can expire or be archived.

Successful runs with observations but no material change event now create a local, deterministic run-summary memory in the same SQLite transaction as run completion. Summaries contain bounded observation counts and a small sample of host/HTTP endpoint keys—not response bodies—and are linked to the run and scope hash. The latest quiet-run summary for the same stage/scope supersedes the prior active one; older records remain in history. These summaries are observations only, expire after 30 days, and do not validate vulnerability findings or authorize actions. Material changes continue through the separate event-triage handoff path.

Complete Nuclei runs also capture up to 20 detections as `finding_candidate` memory linked to that run and scope, with 30-day expiry. The records preserve the scanner's sanitized structured observation and explicitly remain unverified; partial runs do not create them, and no automated path promotes a candidate to reproduced or validated.

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

Amass, Uncover, Gau, AlterX, DNSx, HTTPx, TLSx, Nmap, Katana, FFUF, and Nuclei are integrated for existing recon workflows. OSINT tool selection and the FFUF wordlist/Nuclei template paths are currently configured through environment variables; schedules, ports, limits and deny-by-default agent policy are stored per program. The deterministic event-triage worker is active. The LLM can now run a bounded synchronous adaptive cycle using the native metered HTTP HEAD probe, and explicit plans may dispatch either the HTTP or TLS native probe. Autonomous daemon dispatch, multi-adapter execution of subprocess tools, and vulnerability validation/reporting remain future work. External subprocess tools are not available to the agent because their actual request counts cannot yet be enforced.
