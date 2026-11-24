# HEIMDALL — Roadmap de desenvolvimento

**Documento consolidado.** Este ficheiro era anteriormente um documento único. O conteúdo foi fundido, deduplicado e dividido por blocos em `roadmap/`. O antigo `docs/ROADMAP_AGENTIC_SECURITY.md` também foi integrado e removido.

**Consolidação:** 2026-11-13
**Estrutura:** 23 ficheiros temáticos, todos com menos de 300 linhas.
**Linguagem principal:** Go · **Browser Automation:** Python + Playwright · **Interfaces:** CLI, TUI e Discord

---

## Índice

| # | Documento | Conteúdo |
|---|---|---|
| 01 | [Visão e princípios](roadmap/01-visao-e-principios.md) | Objetivo do projeto, visão, aprendizagem operacional e princípios arquiteturais |
| 02 | [Interfaces](roadmap/02-interfaces.md) | CLI, TUI e Discord: responsabilidades, comandos, aprovações e segurança |
| 03 | [Arquitetura geral](roadmap/03-arquitetura.md) | Diagrama de camadas, componentes e fluxo de coordenação |
| 04 | [Autonomous Agent Runtime](roadmap/04-agent-runtime.md) | Ciclo do agente, planeamento, autonomia, limites e agentes futuros |
| 05 | [Program Intelligence](roadmap/05-program-intelligence.md) | Regras por programa, hierarquia de políticas, headers obrigatórios e contas de teste |
| 06 | [Policy Engine](roadmap/06-policy-engine.md) | Scope, validação, controlo de impacto e decisões ALLOW/DENY/REQUIRE_APPROVAL |
| 07 | [Tool Registry e Execution Layer](roadmap/07-tool-registry-e-execution.md) | Metadados de ferramentas, categorias, ferramentas prioritárias e execução |
| 08 | [Reconnaissance Engine](roadmap/08-reconnaissance.md) | Pipeline e etapas 1–8: scope, passivo, DNS, HTTP, fingerprinting, crawling |
| 09 | [JavaScript e descoberta](roadmap/09-javascript-e-descoberta.md) | Etapas 9–15: JavaScript Intelligence, endpoints, parâmetros, conteúdo, Nuclei e correlação |
| 10 | [Browser Automation](roadmap/10-browser-automation.md) | Playwright, componentes, browser recon, testes assistidos e handoff |
| 11 | [Target Knowledge Engine](roadmap/11-target-knowledge.md) | Entidades, relações, provenance, memória por alvo e contas de teste |
| 12 | [Business Logic Intelligence](roadmap/12-business-logic.md) | Fluxos, estados, regras de negócio e formulação de hipóteses |
| 13 | [Findings Manager](roadmap/13-findings-manager.md) | Tipos de descoberta, estrutura, estados, evidências e validação humana |
| 14 | [Discord Notification Service](roadmap/14-discord.md) | Eventos, notificações, deduplicação, prioridades, botões e aprovações |
| 15 | [Providers, persistência e reporting](roadmap/15-providers-persistencia-reporting.md) | Providers, Model Router, SQLite/evolução e Reporting Engine |
| 16 | [Segurança, observabilidade e benchmarks](roadmap/16-seguranca-observabilidade-benchmarks.md) | Prompt injection, secrets, browser worker, auditoria e métricas |
| 17 | [Roadmap de fases](roadmap/17-roadmap-de-fases.md) | 12 fases de implementação, com objetivos e resultados esperados |
| 18 | [Estrutura e stack](roadmap/18-estrutura-e-stack.md) | Árvore de diretórios, stack tecnológica e decisões estruturais |
| 19 | [Prioridades e critérios](roadmap/19-prioridades-e-criterios.md) | Prioridades imediatas, critérios de sucesso e ciclo operacional |
| 20 | [Visão final](roadmap/20-visao-final.md) | Capacidades diferenciadoras, ciclo central e resultado pretendido |
| 21 | [Estado atual e gates](roadmap/21-estado-atual-e-gates.md) | O que já está implementado, limites atuais e gates de aceite |
| 22 | [Workspace/Code mode](roadmap/22-workspace-code-mode.md) | Segundo modo de trabalho, isolamento, sandbox e verificação de código |
| 23 | [Operação e deploy](roadmap/23-operacao-e-deploy.md) | Topologia VPS, packaging, segredos, backups, observabilidade e runbook |

---

## Como esta consolidação foi feita

O documento original continha duas versões do mesmo roadmap:

- **v1:** 22 secções, com Planeamento, Event System, Observabilidade, Benchmarks, Estrutura de diretórios, Decisões técnicas, Critérios de sucesso e uma visão final mais detalhada.
- **v2:** 21 secções, mais recente, com Program Intelligence, contas de teste, Browser Automation Engine, Segurança interna do Heimdall e Stack tecnológica.

O texto repetido foi mantido uma única vez. O conteúdo exclusivo de cada versão foi preservado. Onde havia divergência, foi aplicada a seguinte resolução:

| Tema em conflito | Decisão |
|---|---|
| Estados de Finding | Máquina da v1 (10 estados), com `REPRODUCED` acrescentado entre `VALIDATING` e `CONFIRMED`, e tabela de equivalência para os termos da v2 |
| Browser Automation | Fase 5 da v2, antes do Reconnaissance Engine |
| Planner | Capacidade interna do Agent Runtime, sem fase própria |
| TUI | Mantida na fase final |
| Agentes especializados | Lista da v2 (9 agentes, incluindo Authentication Agent) |
| Burp Suite e OWASP ZAP | Mantidos como ferramentas prioritárias |
| Papel do Discord | Principal canal remoto, complementar à CLI/TUI |
| Comandos Discord | União dos comandos de validação (v1) com aprovações/agente/memória (v2) |
| Observabilidade | `slog` agora; OpenTelemetry como evolução futura |
| Providers | OpenAI e OpenCode Zen iniciais; Anthropic e locais futuros |
| Estrutura de diretórios | Árvore da v1 com adição de `browser/` (worker Python) |
| Âmbito do Findings Manager | Modelo amplo da v1 (todas as descobertas), com severidade e impacto da v2 |
| Princípios | Lista única fundida a partir dos 8 princípios da v1 e dos 10 da v2 |
| Prioridades imediatas | Sequência da v2 (Policy e Request Middleware antes do Browser e do Recon) |

O `ROADMAP_AGENTIC_SECURITY.md` contribuiu com material que as duas versões não tinham:

| Tema | Decisão |
|---|---|
| Estado de implementação | Preservado em `21-estado-atual-e-gates.md`, para as fases não repetirem trabalho feito |
| Workspace/Code mode | Preservado em `22-workspace-code-mode.md` como trilha própria, isolada do engagement |
| Findings | Adotado o ciclo `candidate → reproduced → validated`, com `REPRODUCED` na máquina de estados |
| Adapters e MCP | Adicionado catálogo de adapters e a regra "MCP é protocolo, não confiança" |
| Subprocessos | Mantidos no recon normal; inelegíveis para ciclos autónomos até cumprirem accounting de request, isolamento de egress e validação de argumentos |
| Ledger e consentimento | Integrados no Policy Engine: reservas idempotentes, quotas, revalidação JIT e falha fechada |
| Gates | Integrados em `19` e `21`, incluindo os critérios globais de aceite |

## Leitura recomendada

1. **Para contexto:** `01` → `03` → `04`.
2. **Para segurança e regras:** `05` → `06` → `16`.
3. **Para implementação:** `17` → `18` → `19` → `21`.
4. **Para operação:** `23` → `21`.
5. **Para a visão de produto:** `20` → `22`.

---

## Checklist de desenvolvimento

`[ ]` pendente · `[x]` concluído

Um item só deve ser marcado quando o **gate** da fase for cumprido. O detalhe de cada fase está em `17-roadmap-de-fases.md`; o estado real do código e os gates completos estão em `21-estado-atual-e-gates.md`. Nenhum item está pré-marcado: confirmar contra o código antes de assinalar.

### Fase 1 — Core e Providers

- [x] Rever e estabilizar a estrutura Go existente
- [x] CLI consolidada com Cobra
- [x] Configuração (Viper) e logging (`slog`)
- [x] Interface comum de providers
- [x] OpenAI e OpenCode Zen integrados
- [x] Testes base e tratamento de erros
- [x] **Gate:** providers intercambiáveis sem alterar o Agent Runtime

**Evidência (2026-11-16):** `make check` verde (formatação, módulos, arquitetura, tamanho, vet, lint, Staticcheck, govulncheck, testes com race e build). Configuração em `internal/config` (Viper; flag > ambiente > ficheiro > defaults) e logging em `internal/logging` (`slog`). O planner e o executor recebem `providers.Provider`; os testes usam `fakePlanModel` e `adaptiveModelStub`, e a única chamada à factory concreta em runtime é o default injetável de `AgentCycleWorker.NewProvider`.

### Fase 2 — Autonomous Agent Runtime

- [x] Ciclo do agente: objetivo → plano → ação → avaliação
- [x] Gestão de contexto, histórico e compressão
- [x] Limites de iteração, timeouts e cancelamento
- [x] Planner interno: tarefas, dependências e replan
- [x] Consulta à memória antes de planear
- [x] **Gate:** o agente conclui uma tarefa simples e para nos limites definidos

**Evidência (2026-11-16):** `make check` verde. `RunAdaptive` relê scope, policy e budgets a cada passo, pede uma ação por chamada, valida, executa e realimenta o resultado; `TestAdaptiveCycleUsesOnlyBoundedResultsAndStopsAtModelDecision` prova a execução de duas ações e a paragem em `planner_stopped` ao atingir o limite. O contexto é limitado por `context_max_bytes` (16 KiB–1 MiB), com truncagem determinística dos turnos antigos, marcador explícito e auditoria em log/metadata (`internal/agent/context.go`). `SIGINT`/`SIGTERM` cancelam toda a CLI e fecham action runs/cycle jobs em curso como `failed` (`TestAdaptiveCycleClosesFailedRunOnCancellation`). A memória é opt-in, same-program, freshness-filtered e auditada. O planner aceita planos planos ou um grafo de até 10 tarefas com `depends_on`: valida ids únicos, dependências existentes e ausência de ciclos, achata as ações em ordem topológica determinística e regista as tarefas na validação de policy (`internal/agent/tasks.go`, `TestOrderPlanTasksRunsDependenciesFirst`, `TestGeneratePlanOrdersTasksAndRecordsSummaries`). O replan continua passo-a-passo no ciclo adaptativo; cada novo passo volta a passar por policy e budgets.

**Reclassificado:** Function Calling / tool calling nativo foi movido para a Fase 3, porque depende do Tool Registry e do schema de ferramentas. Está agora implementado em modo opt-in: o planner envia `tools` apenas quando `WithToolRegistry`/`--tools` é usado e mantém o contrato JSON próprio (`{"actions":[...]}` ou `{"tasks":[...]}`) como fallback.

### Fase 3 — Tool Registry e Execution Layer

- [x] Metadados e schemas de ferramentas
- [x] Registo, consulta e validação de argumentos (catálogo compilado)
- [x] Function Calling / tool calling nativo (reclassificado da Fase 2)
- [x] Execução Go/Python/Shell com timeouts e limites de recursos
- [x] Perfil de subprocesso com negação de rede e filesystem efémero (não registado no catálogo)
- [x] Normalização de resultados e preservação de logs
- [x] Catálogo de adapters com classe de risco, scope e accounting
- [x] Modelo de isolamento e accounting de subprocessos documentado (nenhum subprocesso admitido)
- [x] Segundo adapter nativo (TLS) e dispatch multi-tool por proposta
- [ ] **Gate:** nenhuma ferramenta executa fora do Registry

**Evidência parcial (2026-11-17):** `internal/recon/agent_tool_schema.go` define `AgentToolSpec` com `id`, `stage`, `class`, `description`, `max_targets`, argumentos tipados e `accounting`; `Validate` rejeita metadados incompletos, classes não suportadas e argumentos desconhecidos. `NewAgentActionRegistry` valida a lista compilada, rejeita adapters nulos e ids duplicados, e `Specs`/`Lookup` expõem o catálogo ordenado. `AgentActionRegistry.Execute` valida stage, número de targets, budget por target, targets vazios e comprimento máximo **antes** de chamar o adapter; um pedido inválido nunca chega ao transporte. `heimdall agent tools [--json]` lista o catálogo sem base de dados, provider, rede ou shell. Testes: `TestAgentRegistryRejectsInvalidMetadata`, `TestAgentRegistryValidatesRequestBeforeAdapterRuns`, `TestAgentRegistryRejectsUnknownToolBeforeExecution`, `TestAgentToolsListsOnlyTheCompiledAgentCatalog`.

**Evidência — Function Calling (2026-11-18):** `providers.Request` passou a ter `Tools []ToolDefinition` e `providers.Response` a ter `ToolCalls []ToolCall`. `providers/tools.go` limita o catálogo a 16 definições, 20 chamadas por resposta e 8 KiB de argumentos, exige nomes `[a-z0-9_]`, schema `object` sem propriedades adicionais, `required` declarado e arrays de strings com limites; chamadas não declaradas, ids repetidos, argumentos não-objeto ou JSON inválido são rejeitados com `ErrInvalidToolCall`/`ErrInvalidToolDefinition`. `providers/openai.go` serializa `tools` como `type:"function"` na Responses API, preserva texto e itens `function_call` (`call_id` com fallback para `id`), e mantém inválida uma resposta sem texto nem chamada. `internal/agent/function_calling.go` converte `AgentToolSpec` em `ToolDefinition` apenas para estágios/classes permitidos pela policy, ativa o modo por `WithToolRegistry`, revalida cada chamada contra o Registry e o schema, e converte-a num `ActionProposal` com `scope_hash` e `estimated_calls = len(targets)`; `PlanValidation.tool_calls` registra a origem. A CLI expõe `agent propose --tools` (sempre com `--send-context`) e continua a não executar ferramentas. Testes: `TestOpenAIGenerateSerializesToolsAndDecodesFunctionCalls`, `TestOpenAIGenerateRejectsUnreviewedToolCalls`, `TestGeneratePlanConvertsNativeToolCalls`, `TestGeneratePlanRejectsUnusableNativeToolCalls`, `TestGeneratePlanRejectsToolCallsWithoutAdvertisedRegistry`, `TestGeneratePlanRejectsToolRegistryOutsideThePolicy`.

**Evidência — Normalização e logs (2026-11-18):** `internal/recon/agent_result.go` introduz `AgentOutcome` (target, método, status code, resultado) e `LogEntry` (timestamp, nível, evento, target, detalhe), ambos limitados e sem headers, bodies ou credenciais. `NormalizeAgentCollection` devolve uma cópia determinística: preenche `tool_version` e `observed_at` das observações, normaliza método/resultado, limita a 10 000 outcomes e 2 048 logs, corta detalhes a 512 bytes em fronteiras UTF-8 válidas e nunca muta as slices do chamador. O `native_http_probe` emite `probe_started`, `request_completed`, `request_failed`/`request_timeout` e `probe_completed`, preenche a metadata das observações e produz um outcome por target. A camada de execução normaliza a coleção e persiste `profile_version`, `outcomes` e `logs` no `result_json` de cada action run, agregando-os também no resultado do plano; `agent action-run` mostra-os sem abrir uma superfície de shell. Testes: `TestNormalizeAgentCollectionFillsMetadataAndBoundsSlices`, `TestNormalizeAgentCollectionNormalizesOutcomeLabels`, `TestNormalizeAgentCollectionKeepsTruncatedLogsValidUTF8`, `TestNativeHTTPProbeMakesOneMeteredHeadAndDoesNotFollowRedirects`, `TestExecutorRunsOnlyMeteredNativeProbeAndRejectsReplay`.

**Evidência — Execução controlada (2026-11-18):** `internal/recon/agent_exec.go` define `AgentExecSpec`/`AgentExecRequest`/`AgentExecResult` e `AgentExecRunner`. O spec exige id revisto, linguagem `go`/`python`/`shell`, binário absoluto e limpo, `argv` fixo, allowlist exata de argumentos extra, ambiente revisto, `network = none`, `filesystem = ephemeral_tmp` e limites de stdin/stdout/stderr/timeout. Specs de interpretadores rejeitam `-c`, `-ec` e `--command`, pelo que não há execução de strings de comando. O runner usa `exec.CommandContext` sem shell, ambiente sanitizado (`safeToolEnvironment` + entradas revistas, com chaves de loader/interpretador reservadas), `HOME`/`TMPDIR` no diretório efémero, `stdin` limitado, buffers com caps, `WaitDelay`, exit code e `ErrAgentExecRejected`/`ErrAgentExecTimeout`/`ErrAgentExecCanceled`/`ErrAgentExecExit`/`ErrOutputLimit`/`ErrAgentExecSandboxUnavailable`. Em Unix, o processo corre num process group próprio e o timeout/cancelamento mata o grupo (`agent_exec_process_unix.go`); há fallback portável. O núcleo não está registado no `AgentActionRegistry` nem exposto ao modelo. Testes: `TestAgentExecSpecRejectsUnsafeMetadata`, `TestAgentExecRequestRejectsUnallowlistedArguments`, `TestAgentExecRunsLiterallyWithoutShellInterpretation`, `TestAgentExecBoundsStdoutAndStderr`, `TestAgentExecTimesOutAndKillsTheProcess`, `TestAgentExecHonorsCallerCancellation`, `TestAgentExecSanitizesEnvironmentAndAppliesReviewedEntries`, `TestAgentExecRunsReviewedInterpreterScripts`.

**Evidência — Isolamento de subprocessos (2026-11-18):** `AgentExecRunner` passou a exigir um sandbox revisto e um diretório efémero por execução. Em macOS, `agent_exec_sandbox_darwin.go` usa `/usr/bin/sandbox-exec` com um perfil que nega `network*` e `file-write*` fora do diretório efémero, nega leitura de caminhos de credenciais comuns e permite apenas `/dev/null`/stdout/stderr; em Linux, `agent_exec_sandbox_linux.go` usa `bubblewrap` com `--unshare-net`, raiz read-only e bind do diretório efémero, mas só depois de um probe que confirma que o sandbox funciona. Sem sandbox, `Execute` devolve `ErrAgentExecSandboxUnavailable` antes de iniciar o processo. `AgentExecResult.Sandbox` regista a implementação usada. O diretório é resolvido com `EvalSymlinks` para que o perfil corresponda ao caminho real, e é removido no fim. Testes: `TestAgentExecFailsClosedWithoutSandbox`, `TestAgentExecPlatformSandboxConfinesNetworkAndWrites` (escrita dentro do workdir permitida, escrita fora bloqueada, ligação TCP loopback bloqueada, `HOME`/`TMPDIR` no workdir, diretório removido).

**Evidência — Catálogo de adapters (2026-11-18):** `AgentToolSpec` passou a declarar `version`, `stage`, `class`, `origin`, `isolation`, `target_types`, `scope_rule`, `max_targets`, `max_requests`, `accounting` e argumentos. `Validate` rejeita versões fora de `[a-z0-9._-]`, origem diferente de `compiled`, perfil de isolamento diferente de `native_in_process_metered`, tipos de alvo desconhecidos, regras de scope desconhecidas, `max_requests` abaixo de `max_targets` e accounting não suportado; `AutonomousEligible` exige `safe_active` + `compiled` + `native_in_process_metered` + `one_request_per_target` + `program_active_url` + cobertura de requests. O `native_http_probe` declara `native-http-v1`, `http_url`, `program_active_url`, 8 targets/8 requests; o executor usa `spec.MaxTargets`/`spec.TargetMaxLength()`, eliminando a divergência entre catálogo e execução. `agent tools` mostra versão, classe, origem, isolamento, tipos de alvo, scope, limites, accounting e elegibilidade autónoma; `--json` inclui `isolation` e `autonomous`. Testes: `TestDefaultAgentRegistryExposesReviewedNativeProbes`, `TestAgentToolSpecAutonomousEligibility`, `TestAgentRegistryRejectsInvalidMetadata`, `TestAgentToolsListsOnlyTheCompiledAgentCatalog`, `TestPlanToolDefinitionsUsesReviewedSchema`.

**Evidência — Segundo adapter nativo e dispatch multi-tool (2026-11-18):** `native_tls_probe` (`native-tls-v1`) foi acrescentado ao Registry default. Faz um handshake TLS por alvo HTTPS autorizado, com `InsecureSkipVerify` intencional para observar o certificado sem autenticar o par, e regista apenas versão TLS, expiração e emissor truncado; não envia pedido HTTP, corpo nem certificado bruto. O pedido é validado contra `StageWeb` e o scope ativo (`https` apenas, sem userinfo/query/fragmento/duplicados), o meter é debitado **antes** do dial e cada handshake produz um outcome `TLS` e uma observação `tls_probe_result`. `ActionProposal` ganhou `tool` (vazio resolve para `native_http_probe`, ids limitados a `[a-z0-9_]` e 64 bytes), o grant preserva-o e `Revalidate` compara-o. `ExecutePlan` valida cada grant com `Registry.Lookup`, stage/classe, `spec.MaxTargets`, `spec.TargetMaxLength()` e budget; `executeAction` despacha pelo `tool` do grant; `ActionResult`/`storedActionResult` registam `tool`. O ciclo adaptativo continua restrito a `native_http_probe`. `agent plan` e `agent propose` passaram a aplicar `execution.ValidateGrant` no dry-run: ferramenta desconhecida ou grant fora do schema retira todos os `authorized_candidate` e marca `policy_checks_passed=false`, sem executar nem criar action runs. Testes: `TestNativeTLSProbePerformsOneMeteredHandshakePerTarget`, `TestNativeTLSProbeMetersBeforeConnecting`, `TestNativeTLSProbeRejectsNonHTTPSAndOutOfScopeTargets`, `TestExecutorDispatchesTheProposedNativeTLSTool`, `TestExecutorRunsMixedHTTPAndTLSPlanUnderOneBudget`, `TestExecutorRejectsUnknownToolBeforeCreatingAnActionRun`, `TestGeneratePlanPreservesTheNativeToolIdentity`, `TestScopeActionPolicyNormalizesTheToolIdentity`, `TestDefaultAgentRegistryExposesReviewedNativeProbes`, `TestAgentPlanValidatesTheToolRegistry`, `TestValidatePlanToolsRejectsGrantsOutsideTheRegistrySchema`.

**Evidência — Isolamento e accounting de subprocessos (2026-11-18):** `roadmap/24-isolamento-e-accounting-de-subprocessos.md` define o princípio (accounting real antes do envio, egress contido, filesystem contido), o perfil admitido `native_in_process_metered` e os perfis futuros `subprocess_network_denied` e `subprocess_metered_proxy` com requisitos de sandbox, rlimits, proxy medido e kill switch. O documento fixa dez critérios de admissão com evidência exigida, falha fechada e o estado actual: os dois probes nativos são elegíveis e nenhum subprocesso está registado. `AgentToolSpec.Isolation` torna o perfil explícito no catálogo; `Validate` rejeita qualquer valor diferente de `native_in_process_metered` e `AutonomousEligible` exige-o, pelo que um adapter de subprocesso não pode ser admitido por engano. Testes: `TestAgentRegistryRejectsInvalidMetadata` (isolamento vazio e `subprocess_metered_proxy`), `TestAgentToolSpecAutonomousEligibility`, `TestAgentToolsListsOnlyTheCompiledAgentCatalog`.

**Evidência — Request profile e middleware (2026-11-20):** `internal/assessment/request_profile.go` define `RequestProfile`/`RequestHeader` com `User-Agent` por omissão, até 16 headers, normalização canónica, ordenação determinística e revisão. Rejeita nomes inválidos, duplicados, valores vazios, CR/LF, bytes não imprimíveis, limites excedidos e headers de framing/credenciais (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `User-Agent`). `internal/store/migrations/025_program_request_profiles.sql` cria o perfil por programa e `SetProgramRequestProfile` só incrementa a revisão quando o perfil normalizado muda. `recon.ApplyRequestProfile` aplica-o aos pedidos do `native_http_probe` antes do envio, e `recon.RequestProfileHTTPArgs` aplica-o ao `httpx` do estágio web e aos estágios `katana`, `ffuf` e `nuclei`; o `tlsx` não envia headers HTTP. A validação do perfil acontece antes de qualquer tool ser resolvida ou lançada, e o fingerprint do perfil entra na `ProfileVersion` de cada estágio. O executor lê o perfil antes de reservar a ação, passa-o no `StageRequest` e persiste `request_profile_revision` no `result_json`; o daemon lê o perfil antes de cada run. Valores de headers nunca entram em logs, outcomes, observações ou artefactos. Testes: `TestNormalizeRequestProfileCanonicalizesAndSortsHeaders`, `TestNormalizeRequestProfileRejectsUnsafeHeaders`, `TestProgramRequestProfileDefaultsAndIsRevisionedPerProgram`, `TestNativeHTTPProbeAppliesTheProgramRequestProfileWithoutLoggingValues`, `TestNativeHTTPProbeRejectsAnInvalidProfileBeforeTheMeter`, `TestRequestPolicyMiddlewareAppliesAndRendersTheProfile`, `TestRequestPolicyMiddlewareRejectsAnUnsafeProfile`, `TestHTTPStageCollectorsApplyTheProgramRequestProfile`, `TestHTTPStageCollectorsRejectAnInvalidProfileBeforeRunningATool`, `TestHTTPStageProfileVersionsChangeWithTheRequestProfile`, `TestExecutorAppliesTheProgramRequestProfileAndPersistsItsRevision`, `TestDaemonPassesTheProgramRequestProfileToTheStage`, `TestProgramRequestProfileRoundTripAndRejectsUnsafeHeaders`.

**Evidência — Decisões explícitas, impacto e aprovações (2026-11-22):** `internal/agent/contract/approval.go` define `Decision` (`ALLOW`/`DENY`/`REQUIRE_APPROVAL`), `ActionImpact` (`passive`/`low`/`active`/`high`), `ApprovalSubject` canónico e `ActionApproval` single-use. `ScopeActionPolicy.Evaluate` devolve sempre uma decisão tipada; `Authorize` mantém-se como wrapper para chamadores que só precisam de gate e `PolicyDecisionError` transporta a decisão. Cada classe mapeia para um impacto fixo (`passive`→`passive`, `safe_active`→`active`, `sensitive`→`high`). `ProgramAgentPolicy.ApprovalRequiredClasses` exige que a classe esteja também em `AllowedClasses`. A aprovação vincula `program_id`, `scope_hash`, `policy_revision`, estágio, ferramenta, classe, impacto, targets canónicos e `request_budget` num fingerprint SHA-256; a seleção é exata e falha fechada em approvals pendentes, expiradas, consumidas, negadas, ambíguas ou com fingerprint divergente. `agent plan`/`agent propose` expõem `decision`, `impact`, `approval_fingerprint` e `approval_subject`, e retiram todos os `authorized_candidate` quando o plano não é integralmente `ALLOW`. `internal/store/migrations/027_agent_action_approvals.sql` acrescenta `approval_required_classes_json` e a tabela `agent_action_approvals`; `CreateAgentApprovalRequest` revalida programa, scope, revisão de policy e allowlists, `DecideAgentApproval` revalida antes de aprovar e `ListUsableAgentApprovals` só devolve approvals aprovadas e não expiradas. `ReserveAgentAction` consome a aprovação na mesma transação da reserva de budget, e `StartAgentAction` volta a validar o grant. A CLI expõe `program policy set --require-approval-class` e `agent approvals list|request|approve|deny`; pedir aprovação lê o mesmo JSON de `agent plan`, cria apenas pedidos para ações `REQUIRE_APPROVAL` e nunca executa ferramentas. Testes: `TestApprovalSubjectCanonicalizesAndFingerprints`, `TestApprovalSubjectRejectsUnsafeInput`, `TestActionApprovalValidationAndEffectiveStatus`, `TestScopeActionPolicyReturnsExplicitDecisions`, `TestAgentApprovalRequestLifecycle`, `TestAgentApprovalRejectsStaleOrUnsafeRequests`, `TestExecutorRequiresAndConsumesScopedApproval`, `TestAgentApprovalsRequestApproveDenyRoundTrip`.

**Evidência — Kill switch global (2026-11-24):** `internal/store/migrations/028_system_kill_switch.sql` cria uma única linha `system_kill_switch` com `engaged`, operador, motivo, timestamp e uma `revision` monotónica. `SetKillSwitch` exige operador e motivo em ASCII imprimível dentro dos limites, grava a transição e é idempotente quando o estado não muda; `GetKillSwitch` devolve o estado observável e uma linha ausente é erro, nunca release implícito. O sentinela `ErrKillSwitchEngaged` marca toda a recusa. A revalidação é just-in-time: `loadAgentExecutionSnapshot` lê o switch e `validateAgentExecutionSnapshot` falha fechado, pelo que `CreateAgentActionRun`, `ReserveAgentAction`, `StartAgentAction` e `ConsumeAgentActionRequest` não criam, reservam, iniciam nem debitam requests enquanto estiver engatado. `ClaimAgentCycleJobs` e `ClaimDueSchedules` não reclamam trabalho, e `ValidateRunAuthorization` junta o switch à verificação de autorização para recusar runs agendados já em lease. A CLI expõe `heimdall kill-switch status [--json]`, `engage` e `release`, sempre com `--by` e `--reason`, e mostra a revisão auditável. Budgets e quotas mantêm-se os já implementados: reservas idempotentes por action run, limites por ação/run e quotas UTC de ciclos/requests por programa. Testes: `TestKillSwitchStateIsAuditableAndIdempotent`, `TestKillSwitchBlocksAgentExecutionAndScheduling`, `TestKillSwitchRoundTrip`.

**Evidência — Contas de teste e acesso a dados (2026-11-20):** `internal/assessment/test_accounts.go` define `DataAccessPolicy` e `TestAccount`. O modo único é `test_accounts_only`, `allow_other_users_data` é rejeitado se verdadeiro e a política predefinida admite contas próprias e explicitamente autorizadas. `NormalizeTestAccount` canonicaliza o id para minúsculas, exige identidade ASCII imprimível, papel `user`/`administrator`/`other`, estado `authorized`/`revoked`, origem `owned`/`explicitly_authorized` e, quando presente, uma referência `env:NAME`; valores de credenciais em bruto são rejeitados. `AuthorizeTestAccount` falha fechado para contas revogadas, fontes desativadas ou políticas que autorizem dados de terceiros. `internal/store/migrations/026_program_data_access.sql` cria `program_data_access` (com `CHECK (allow_other_users_data = 0)`) e `program_test_accounts`; `Get/SetProgramDataAccess` só incrementam a revisão quando a política muda, e `Add/List/RevokeProgramTestAccount` guardam apenas metadados e nunca resolvem a referência da credencial. A CLI expõe `program data-access show|set` e `program accounts list|add|revoke`, com o resumo no `program show`; `accounts add` aceita apenas o nome da variável de ambiente e não lê o segredo. Testes: `TestNormalizeDataAccessPolicyDefaultsAndRejectsWidening`, `TestNormalizeTestAccountCanonicalizesMetadata`, `TestNormalizeTestAccountRejectsUnsafeMetadata`, `TestAuthorizeTestAccountEnforcesTheDataAccessPolicy`, `TestProgramDataAccessDefaultsAndRevision`, `TestProgramTestAccountLifecycle`, `TestProgramDataAccessAndTestAccountsRoundTrip`.

### Fase 4 — Policy Engine e Program Intelligence

- [x] Programs, targets e scope tipado (portas, exclusões, precedência)
- [x] Regras por programa, headers obrigatórios e User-Agent
- [x] Request Policy Middleware
- [x] Contas de teste e restrição de acesso a dados
- [x] Aprovações, níveis de impacto e rate limits
- [x] Ledger, budgets, quotas e kill switch
- [x] **Gate:** zero request sem autorização atual; decisões `ALLOW`/`DENY`/`REQUIRE_APPROVAL`

**Evidência — Browser Worker loopback e isolamento de sessões (2026-11-24):** `browser/heimdall_browser` implementa o worker Python com servidor HTTP apenas em `127.0.0.1`, token obrigatório vindo de `HEIMDALL_BROWSER_TOKEN` (32–256 bytes ASCII imprimíveis, comparação em tempo constante) e rotas versionadas `/healthz` e `/v1/sessions`. Os corpos são limitados a 16 KiB, exigem `Content-Length`, rejeitam `Transfer-Encoding`, JSON duplicado, constantes não finitas, UTF-8 inválido, campos desconhecidos e query strings; as respostas usam `Cache-Control: no-store` e nunca incluem cookies, tokens, storage state ou credenciais. O `SessionManager` gera ids UUID, mantém no máximo uma sessão por par (programa, conta de teste), permite o mesmo account id noutro programa, impõe um cap de 8 sessões (máximo 32) e falha fechado com `driver_unavailable` (HTTP 503). `UnavailableDriver` é o default até à integração do Playwright, pelo que nenhuma sessão de browser é criada nesta fase. Em Go, `internal/browser` define o contrato e um cliente que recusa URLs não-loopback, `https`, userinfo, path, query ou fragmento, limita respostas a 256 KiB, não segue redirects, valida o eco exato de programa/conta/scope/policy revision e mapeia erros para sentinelas sem expor o token. `heimdall browser health [--json]` faz o handshake autenticado. Testes: `test_protocol`, `test_sessions`, `test_server` (Python) e `TestNewClientRejectsUnsafeConfiguration`, `TestClientHealth`, `TestClientSessionLifecycle`, `TestClientMapsWorkerErrors`, `TestClientRejectsProtocolViolations`, `TestBrowserHealthCommand`. Playwright/Chromium, Browser Manager, navegação, observação de rede, inspectores, evidências e handoff continuam pendentes.

### Fase 5 — Browser Automation Engine

- [ ] Python Worker com Playwright
- [ ] Browser Manager e Session Manager
- [ ] Navigation Engine e Network Observer
- [ ] DOM Inspector e JavaScript Inspector
- [ ] Evidence Collector
- [ ] Test Executor com validação de políticas
- [ ] Browser Handoff
- [ ] **Gate:** sessões isoladas por conta de teste e sem fuga de cookies/tokens

### Fase 6 — Reconnaissance Engine

- [ ] Pipeline passivo → ativo → correlação
- [ ] Subdomain Enumeration, DNS Resolution e HTTP Probing
- [ ] Technology Fingerprinting, Historical URLs e Crawling
- [ ] JavaScript Intelligence
- [ ] Endpoint, Parameter e Content Discovery
- [ ] Public Exposure Intelligence e Nuclei
- [ ] Correlação e atualização do conhecimento
- [ ] **Gate:** resultados estruturados, deduplicados e reutilizáveis

### Fase 7 — Target Knowledge Engine

- [ ] Modelo de entidades e relações
- [ ] Provenance, confiança e freshness
- [ ] Memória isolada por programa/alvo
- [ ] FTS, archive/restore e supersessão
- [ ] Atualização automática e reutilização
- [ ] **Gate:** zero memória factual cross-program/cross-workspace

### Fase 8 — Findings Manager

- [ ] Modelo de Finding e tipos de descoberta
- [ ] Estados (incluindo `REPRODUCED`) e transições
- [ ] Evidências, severidade, impacto e confiança
- [ ] Deduplicação
- [ ] Validação humana e feedback para a memória
- [ ] **Gate:** `candidate`/`reproduced`/`validated` auditáveis e sem promoção automática

### Fase 9 — Discord Integration

- [ ] Bot, autenticação, allowlist e RBAC
- [ ] Event System e Notification Service
- [ ] Notificações, deduplicação e prioridades
- [ ] Consulta, validação e notas
- [ ] Aprovações e Browser Handoff
- [ ] Auditoria das ações
- [ ] **Gate:** nenhuma ação fora da Application Layer; sem credenciais no Discord

### Fase 10 — Business Logic Intelligence

- [ ] Identificação de fluxos, estados e transições
- [ ] Regras de negócio e dependências
- [ ] Comparação entre contas de teste
- [ ] Hipóteses de falhas lógicas
- [ ] **Gate:** testes sem dados reais e com evidência para validação manual

### Fase 11 — Multi-Agent Architecture

- [ ] Agentes especializados definidos
- [ ] Coordenação e delegação
- [ ] Políticas e memória aplicadas a todos os agentes
- [ ] **Gate:** nenhum agente contorna o Policy Engine ou o Tool Registry

### Fase 12 — TUI, benchmarks e melhoria contínua

- [ ] TUI com Bubble Tea
- [ ] Benchmarks e métricas de qualidade/custo
- [ ] Observabilidade (OpenTelemetry quando justificado)
- [ ] PostgreSQL quando o volume o exigir
- [ ] **Gate:** métricas de qualidade, custo e cumprimento de scope publicadas

### Trilha paralela — Workspace/Code mode

- [ ] Indexação read-only do repositório
- [ ] Leitura segura: path traversal, symlinks e limite de tamanho
- [ ] Patches revistos e aplicados apenas ao workspace
- [ ] `go test`, `go vet`, build, SAST, secrets, dependências e IaC
- [ ] Sandbox com limites de filesystem, processo, CPU/memória e rede
- [ ] Saída SARIF e SBOM CycloneDX
- [ ] **Gate:** isolamento entre workspaces e zero rede não declarada

### Operação em VPS

- [ ] Dockerfile/Compose ou unit systemd
- [ ] Utilizador não-root, volume `HEIMDALL_HOME` e root filesystem read-only
- [ ] Healthcheck, restart e logs persistentes com rotação
- [ ] Toolchain e templates com versões fixas
- [ ] Segredos em secret manager, com rotação
- [ ] Egress-only e browser worker em loopback
- [ ] Backup consistente e restore ensaiado
- [ ] Retenção de artefactos e quota de disco
- [ ] Métricas, alertas e dead-man's switch
- [ ] **Gate:** restart não duplica efeitos, restore foi testado e não há segredos em logs

### Transversal (contínuo)

- [ ] CI com testes offline/loopback
- [ ] Fixtures de autorização, scope drift, expiração, cancelamento e crash
- [ ] Documentação e ADRs atualizados
- [ ] Auditoria, redaction e gestão de secrets revistas
- [ ] Revisão dos gates de `21` antes de cada release
