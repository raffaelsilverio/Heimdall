# Estado atual e gates

Este documento descreve o estado de implementação conhecido e os critérios de aceite que qualquer fase deve cumprir.

**Não é um roadmap paralelo.** O roadmap oficial está em `17-roadmap-de-fases.md`; este ficheiro existe para que as fases não repitam trabalho já feito e para que as fronteiras de segurança não se percam.

**Última revisão do estado:** 2026-11-16.

## Modelo de operação

O Heimdall corre como serviço agendado, não como agente sem supervisão:

- A descoberta, a triagem e a correlação podem ser autónomas.
- As ações são limitadas por política, consentimento, budgets e quotas.
- A confirmação de vulnerabilidades e a submissão de relatórios são humanas.

O daemon é o processo principal; a CLI serve para operação e o Discord para supervisão. O deploy está descrito em `23-operacao-e-deploy.md`.

## Implementado

- Fase 1 (Core e Providers) concluída: CLI Cobra, configuração e logging validados, e providers OpenAI/OpenCode Zen atrás de `providers.Provider`; planner e executor não dependem de implementações concretas.
- Configuração resolvida por precedência flag > ambiente > `<home>/config.yaml` > defaults, com validação fail-closed de provider e logging; API keys continuam apenas no ambiente.
- Logger `slog` global configurável por `--log-level`/`--log-format` (`text` ou `json`), partilhado por CLI, daemon e scheduler.
- Providers OpenAI e OpenCode Zen com timeout por pedido configurável (`1s`–`10m`), rótulos de erro por provider e erros sentinela para auth, rate limit, 5xx, timeout e resposta inválida.
- `SIGINT`/`SIGTERM` cancelam toda a CLI; action runs e cycle jobs em curso são fechados como `failed` com uma janela de persistência não cancelável.
- Contexto de conversação limitado por `context_max_bytes` (16 KiB–1 MiB, default 256 KiB), com truncagem determinística dos turnos mais antigos, marcador explícito de omissão e contagens auditadas em log e metadata; system messages e o prompt mais recente nunca são descartados. Não há sumarização por modelo.
- Programas com autorização/expiração, scope tipado, portas, precedência de exclusão, schedules e limites.
- Sincronização HackerOne read-only com snapshots, revisão pendente e pausa; a aprovação nunca reativa automaticamente o programa.
- SQLite/FTS com memória estritamente por `program_id`, proveniência e hashes, validade, supersessão, pesquisa/lista/show/archive/restore.
- Resumos locais de runs completos sem evento material e captura automática de até 20 resultados Nuclei completos como `finding_candidate`. Nenhum é promovido automaticamente a achado validado.
- Triagem de eventos separada da fila de ciclos adaptativos, com leases e handoffs determinísticos.
- Política de ação por programa deny-by-default; `agent plan` valida JSON sem executar.
- `agent propose` envia contexto ao modelo apenas com `--send-context`; memória exige também `--include-memory`.
- Briefings de memória limitados em `run`, `agent propose` e triagem, sempre same-program e freshness-filtered.
- Ledger durável de action runs, reservas idempotentes, budgets de ação/request, revalidação JIT, accounting por tentativa HTTP, recuperação `uncertain`, revisão auditada e resultado estruturado.
- Um único adapter agentic: `native_http_probe`, que faz uma requisição `HEAD` por alvo, não segue redirects e não recolhe corpos.
- `agent execute` executa um plano explícito sequencial; `agent cycle` faz planeamento adaptativo síncrono, uma proposta por chamada do modelo, limitado por steps/budgets e com opt-ins separados para egress e requests ativos.
- Consentimento persistente e revisto por programa para ciclos futuros; `agent_cycle_jobs` e worker no daemon processam apenas eventos materiais **novos** criados enquanto o consentimento está habilitado. Há quotas UTC de ciclos e requests reservados, leases e falha fechada sem replay automático.
- Inspeção e revisão de action runs e cycle jobs (`agent action-runs`, `agent action-run`, `agent action-review`, `agent cycle-jobs`, `agent cycle-review`).
- O planner aceita uma lista plana de ações ou um grafo de até 10 tarefas com `depends_on`, valida ids/dependências/ciclos e achata as ações em ordem topológica determinística; a validação de policy regista as tarefas revistas. `agent plan` e `agent execute` aceitam `actions` ou `tasks` (nunca ambos).

## Limites atuais

- O daemon só executa ciclos quando existe consentimento persistente válido; programas e consentimentos novos ficam desabilitados por omissão. Não há backfill de eventos anteriores ao consentimento.
- A única ação agentic é o probe HTTP nativo. Os adaptadores existentes via subprocesso continuam disponíveis nos fluxos normais de recon, mas **não** no executor agentic, porque o tráfego interno não passa pelo meter Go.
- Os providers não fazem retry automático; 429, 5xx e timeouts são devolvidos ao chamador como erros tipados para decisão explícita.
- A compressão de contexto é determinística (descarte dos turnos mais antigos); não há sumarização por modelo.
- Function Calling / tool calling nativo não está implementado: o contrato do planner é JSON próprio (`actions` ou `tasks`) e não envia `tools` ao provider. Foi reclassificado para a Fase 3, dependente do Tool Registry.
- Não há modo de edição de repositório, sandbox de código, workflow de findings reproduzidos/validados nem submissão de reports.
- `finding_candidate` é uma deteção de scanner, não prova de vulnerabilidade. A memória nunca autoriza ações.

## Gates globais

Nenhuma fase é considerada concluída sem provar:

- Zero ação sem autorização atual.
- Zero memória factual partilhada entre programas ou workspaces.
- Zero execução de adapters não registados.
- A memória funciona sem LLM, é recuperada apenas pelo mesmo programa/workspace e cada nota factual aponta para uma fonte ou é explicitamente marcada como anotação do operador.
- Cada request é debitado no ledger antes do envio; consentimento, policy revision, autorização e scope são revalidados; um crash nunca causa replay silencioso; o daemon permanece deny-by-default.
- Nenhuma saída de Nuclei ou LLM é `VALIDATED` sem reprodução/evidência; o relatório exportado é rastreável e não contém segredos, cookies ou tráfego bruto por omissão.
- Testes offline/loopback cobrem scope positivo e negativo, exclusões, portas, redirects, limites, expiração, revogação, timeout, falha de provider e persistência de evidência.
- Nenhum shell/script arbitrário ou adapter fora do catálogo revisto.

## Gates por área

| Área | Gate |
|---|---|
| Autorização e scope | Zero request quando a autorização expirou, o programa pausou, o scope/source mudou, a revisão está pendente, o consentimento expirou/revogou ou o budget acabou |
| Memória | Zero cross-program/cross-workspace em fila, prompt, busca, artefacto e exportação |
| Execução | Cada request ligado a policy revision, programa, scope, run, action e adapter |
| Findings | `candidate`, `reproduced` e `validated` são estados distintos e auditáveis; o LLM não inventa evidência |
| Reporting | Alegações referenciam evidência existente; submissão é um passo humano confirmado |
| Workspace | Repositórios de laboratório validam path traversal, symlinks, exposição de secrets, patch incorreto, comando fora da allowlist, execução sem aprovação e isolamento entre workspaces |

## Gates operacionais

- Um restart não duplica efeitos externos nem perde jobs.
- O restore de um backup foi ensaiado.
- A migração tem rollback documentado.
- A toolchain está fixada e é verificável.
- O disco tem quota e retenção.
- Existe alerta para daemon parado e dead-man's switch.
- Os segredos são rotáveis sem reconstruir a imagem.
- O browser worker está isolado e sem acesso ao host.

## Como usar este documento

- Antes de iniciar uma fase, verificar se parte do trabalho já existe.
- Antes de fechar uma fase, verificar os gates aplicáveis.
- Se o estado do código divergir deste documento, atualizar o documento em vez de assumir que o roadmap está errado.
- Os gates são cumulativos: uma fase nova não pode quebrar um gate de uma fase anterior.
