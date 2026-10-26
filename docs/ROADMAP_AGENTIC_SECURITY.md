# Roadmap: Heimdall como agente de Code/AppSec e Pentest supervisionado

**Atualizado:** 2026-10-26  
**Estado:** Fase 2 iniciada; execução adaptativa limitada e consentimento por programa implementados.

## 1. Visão

Evoluir o Heimdall para uma plataforma com dois modos de trabalho relacionados, mas isolados:

1. **Workspace/Code mode** — experiência iterativa de agente de código: entender um repositório, localizar problemas, propor alterações, executar verificações permitidas e apresentar um diff revisável.
2. **Engagement/Security mode** — agente de bug bounty e pentest autorizado: planejar e executar adaptadores registrados, interpretar resultados, adaptar os próximos passos dentro de uma autorização e produzir achados com evidência.

O objetivo não é dar um terminal irrestrito ao modelo. O modelo propõe; o Heimdall valida contexto, política e limites; adaptadores compilados executam; o ledger registra a ação e sua evidência. O modo de código e o modo de engagement podem compartilhar contratos e infraestrutura, mas **não compartilham memória factual, permissões ou contexto**.

## 2. Estado atual

### Implementado

- Programas com autorização/expiração, scope tipado, portas, precedência de exclusão, schedules e limites.
- Sincronização HackerOne read-only com snapshots, revisão pendente e pausa; aprovação nunca reativa automaticamente o programa.
- SQLite/FTS com memória estritamente por `program_id`, proveniência e hashes, validade, supersessão, busca/lista/show/archive/restore.
- Resumos locais de runs completos sem evento material e captura automática de até 20 resultados Nuclei completos como `finding_candidate`. Nenhum deles é promovido automaticamente a achado validado.
- Triagem de eventos separada da fila de ciclos adaptativos, com leases e handoffs determinísticos.
- Política de ação por programa deny-by-default; `agent plan` valida JSON sem executar.
- `agent propose` envia contexto ao modelo somente com `--send-context`; memória exige também `--include-memory`.
- Briefings de memória limitados em `run`, `agent propose` e triagem, sempre same-program e freshness-filtered.
- Ledger durável de action runs, reservas idempotentes, budgets de ação/request, revalidação JIT, accounting por tentativa HTTP, recuperação `uncertain`, revisão auditada e resultado estruturado.
- Um único adapter agentic: `native_http_probe`, que faz uma requisição `HEAD` por alvo, não segue redirects e não coleta corpos.
- `agent execute` executa um plano explícito sequencial; `agent cycle` faz planejamento adaptativo síncrono, uma proposta por chamada do modelo, limitado por steps/budgets e com opt-ins separados para egress e requests ativos.
- Consentimento persistente e revisado por programa para ciclos futuros; `agent_cycle_jobs` e worker no daemon processam somente eventos materiais **novos** criados enquanto o consentimento está habilitado. Há quotas UTC de ciclos e requests reservados, leases e falha fechada sem replay automático.
- Inspeção/revisão de action runs e cycle jobs (`agent action-runs`, `agent action-run`, `agent action-review`, `agent cycle-jobs`, `agent cycle-review`).

### Limites atuais

- O daemon só executa ciclos quando há consentimento persistente válido; programas novos e consentimentos novos ficam desabilitados por padrão. Não há backfill de eventos anteriores ao consentimento.
- A única ação agentic é o probe HTTP nativo. Os adaptadores existentes via subprocesso continuam disponíveis nos fluxos normais de recon, mas **não** no executor agentic porque seu tráfego interno não passa pelo meter Go.
- Não há modo de edição de repositório, sandbox de código, workflow de findings reproduzidos/validados ou submissão de reports.
- `finding_candidate` é uma detecção de scanner, não prova de vulnerabilidade. Memória não autoriza ações.

## 3. Modos e fronteiras de segurança

### 3.1 Engagement/Security mode

Contexto sempre vinculado a um `program_id`. Antes de cada ação e de cada request, verificar autorização atual, expiração, status, scope/source hash, revisão pendente, política, schedule, limites, lease e orçamento. Mudanças de scope, autorização ou consentimento interrompem o ciclo.

### 3.2 Workspace/Code mode

Contexto sempre vinculado a um `workspace_id` e a um checkout explícito. O workspace não herda fatos de programas de bug bounty; programas não recebem código privado sem egress consentido. Permissões de arquivo e de rede são diferentes das permissões de engagement.

Capacidades pretendidas, todas registradas e tipadas:

- listar arquivos e buscar símbolos/texto dentro do workspace permitido;
- ler arquivos sob limite de tamanho e proteção contra symlink/path traversal;
- gerar um patch revisável e aplicá-lo apenas ao workspace autorizado;
- executar verificações por identificador fixo, como testes, build e scanners aprovados;
- apresentar diff, resultados e evidência para revisão.

Não haverá shell arbitrário, scripts gerados pelo modelo, acesso implícito a `$HOME`, segredos, sockets locais ou rede. Uma capacidade de teste executável deve declarar arquivos/rede permitidos, timeout, CPU/memória e política de saída.

### 3.3 Catálogo de adapters

Cada adapter deve declarar: ID/versão, estágio e classe de risco, tipos de alvo, validação de scope, custo máximo e **como contabiliza cada request**. Apenas adapters compilados ou extensões explicitamente revisadas entram no catálogo. MCP pode ser considerado como protocolo de integração, não como confiança: servidores remotos não podem introduzir ferramentas implicitamente.

Subprocessos não são elegíveis para ciclos autônomos até terem accounting de request confiável, isolamento de egress e validação de argumentos; estimativa por alvo ou parsing de stdout não conta como accounting real.

## 4. Fases

### Fase 0 — contratos e avaliação

**Majoritariamente implementada.** Política por programa, classes, ledger, tipos de memória, consentimentos e estados `uncertain` existem.

Ainda manter/expandir fixtures de autorização, scope/source drift, expiração, revisão pendente, cancelamento, falhas de provider e migrações. Consentimentos persistentes antigos são resetados por migrations que adicionam novos limites/policy binding; o operador deve reaprovar.

**Gate:** testes comprovam zero ação sem autorização atual, zero cross-program memory e zero execução de adapters não registrados.

### Fase 1 — memória isolada e handoffs duráveis

**Implementada na primeira fatia:** memória local por programa, busca lexical, briefings limitados, proveniência, validade, captura de resumos/candidatos, handoffs e fila determinística de triagem com leases.

Possíveis incrementos posteriores: manutenção/decay por categoria, resolução de contradições e melhores ferramentas de inspeção/retention. Nada disso pode transformar memória em fonte de autorização.

**Gate:** memória funciona sem LLM, é recuperada somente pelo mesmo programa/workspace e toda nota factual aponta para uma fonte ou é explicitamente marcada como anotação do operador.

### Fase 2 — planner e autonomia limitada

**Implementada parcialmente:** ledger, request meter nativo, adapter `native_http_probe`, execução síncrona multi-ação e ciclo adaptativo. O daemon consome jobs somente com consentimento persistente por programa; quotas diárias de ciclos e requests são reservadas atomicamente. Jobs e ações expirados não são repetidos automaticamente.

Próximos incrementos:

1. **Concluído — operabilidade de revisão:** inspecionar jobs com `agent cycle-jobs` e registrar avaliação append-once com `agent cycle-review`. A revisão não faz replay; jobs com action runs incertos exigem primeiro `agent action-review`.
2. **Em aberto — quotas e operação:** melhorar painel de quotas/falhas por programa e acrescentar limites explícitos de duração total, concorrência por programa e kill switch observável.
3. **Adapters nativos de baixo impacto:** avaliar DNS/metadata TLS ou API checks somente se cada pacote/request puder ser limitado e contabilizado em runtime. Cada adapter entra com testes offline/loopback e perfil de risco explícito.
4. **Subprocessos:** continuam fora do agente até accounting e isolamento verificáveis. Preferir substituir por implementação nativa instrumentável.

**Gate:** cada request de rede é debitado antes do envio; consentimento, policy revision, autorização e scope são revalidados; crash nunca causa replay silencioso; o daemon permanece deny-by-default.

### Fase 3 — ciclo de findings e reports

**Primeiro passo já iniciado:** Nuclei só produz memória `finding_candidate`, com proveniência do run, scope hash, expiração e aviso explícito de não validação.

Construir um domínio de findings independente da memória, com estados inequívocos:

1. `candidate` — saída de scanner ou hipótese, não confirmada;
2. `reproduced` — reproduzida por um procedimento seguro e específico, com requests/respostas redigidas e ambiente/scope registrados;
3. `validated` — evidência revisada segundo critérios do programa; nunca promoção automática por repetição ou resumo do modelo;
4. `rejected`/`needs_review` — falso positivo, resultado ambíguo ou evidência insuficiente.

Cada transição registra programa, scope/source hash, run/action IDs, adapter/versão, request budget usado, timestamps, nível de confiança, operador/validador e evidências. Reports podem ser redigidos pelo modelo, mas cada alegação deve referenciar evidência existente. Submissão a HackerOne/Bugcrowd permanece um passo humano confirmado.

**Gate:** nenhuma saída de Nuclei/LLM é `validated` sem reprodução/evidência; relatório exportado é rastreável e não contém segredos, cookies ou tráfego bruto por padrão.

### Fase 4 — Workspace/Code mode

Adicionar um modo inspirado no fluxo iterativo de agentes de código: inspecionar → planejar patch → editar dentro do checkout → executar verificações registradas → revisar diff → aprovar.

Prioridade inicial:

- indexação local/read-only do repositório;
- busca e leitura de arquivos limitadas ao workspace;
- patches estruturados, preview e confirmação antes de aplicar;
- ferramentas estáticas registradas para `go test`, `go vet`, build, SAST, secrets, dependências e IaC;
- sandbox de execução com limites de filesystem, processo, CPU/memória e rede;
- saída SARIF e SBOM CycloneDX onde aplicável.

Não compartilhar memória factual entre repositórios ou entre workspace e programa. Nenhuma mudança no código de produção, exploração de sistema local ou acesso à rede ocorre apenas porque o modelo pediu.

**Gate:** testes em repositórios de laboratório validam path traversal, symlinks, exposição de secrets, patch incorreto, comando fora da allowlist, execução sem aprovação e isolamento entre workspaces.

### Fase 5 — avaliação, operação e expansão

Usar laboratórios próprios ou ambientes explicitamente autorizados (por exemplo, OWASP Juice Shop, crAPI, WebGoat e fixtures internas). Medir taxa de achados reproduzidos, falsos positivos, requests, custo, latência, ações bloqueadas e recuperação de crash. Nunca executar esses cenários contra programas reais em CI.

Depois de gates aprovados, considerar outras plataformas, adapters, interface TUI/UI, gestão de equipe e exportações. Vetores, reranking e multi-agent ficam para depois de métricas mostrarem benefício e isolamento.

## 5. Critérios globais de aceite

- Zero vazamento factual entre programas/workspaces, inclusive em fila, prompt, busca, artefato e exportação.
- Zero request quando autorização expirou, programa pausou, scope/source mudou, revisão está pendente, consentimento expirou/revogou ou budget acabou.
- Cada request debitado no ledger antes do envio e ligado a policy revision, programa, scope, run, action e adapter.
- Todo resultado externo tratado como dado não confiável; nenhum corpo bruto enviado ao modelo por padrão.
- Recuperação de crash não repete efeito externo incerto sem decisão explícita.
- Finding candidate, reproduced e validated são estados distintos e auditáveis; LLM não inventa evidência.
- Nenhum shell/script arbitrário ou adapter fora do catálogo revisado.
- Avaliações offline cobrem escopo positivo/negativo, exclusões, portas, redirects, limites, expiração, revogação, timeout, falha de provider e persistência de evidência.
