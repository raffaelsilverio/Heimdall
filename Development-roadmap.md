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

**Reclassificado:** Function Calling / tool calling nativo foi movido para a Fase 3, porque depende do Tool Registry e do schema de ferramentas. O contrato atual continua a ser JSON próprio (`{"actions":[...]}` ou `{"tasks":[...]}`) sem `tools` no `providers.Request`.

### Fase 3 — Tool Registry e Execution Layer

- [ ] Function Calling / tool calling nativo (reclassificado da Fase 2)
- [ ] Metadados e schemas de ferramentas
- [ ] Registo, consulta e validação de argumentos
- [ ] Execução Go/Python/Shell com timeouts e limites de recursos
- [ ] Normalização de resultados e preservação de logs
- [ ] Catálogo de adapters com classe de risco, scope e accounting
- [ ] **Gate:** nenhuma ferramenta executa fora do Registry

### Fase 4 — Policy Engine e Program Intelligence

- [ ] Programs, targets e scope tipado (portas, exclusões, precedência)
- [ ] Regras por programa, headers obrigatórios e User-Agent
- [ ] Request Policy Middleware
- [ ] Contas de teste e restrição de acesso a dados
- [ ] Aprovações, níveis de impacto e rate limits
- [ ] Ledger, budgets, quotas e kill switch
- [ ] **Gate:** zero request sem autorização atual; decisões `ALLOW`/`DENY`/`REQUIRE_APPROVAL`

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
