# Isolamento e accounting de subprocessos

Este documento define as condições mínimas para que uma ferramenta executada por subprocesso possa entrar no catálogo agentic.

**Estado:** modelo definido e perfil `subprocess_network_denied` implementado no núcleo de execução (macOS `sandbox-exec`; Linux `bubblewrap` quando disponível). Nenhum subprocesso está registado no catálogo agentic: os únicos adapters executáveis são `native_http_probe` e `native_tls_probe`, ambos sob o perfil `native_in_process_metered`.

## Princípio

O executor agentic só pode executar um adapter que prove, em código e em testes, três propriedades ao mesmo tempo:

1. **Accounting real:** cada request externo é debitado no ledger **antes** de sair; nada é contado por estimativa, parsing de stdout ou convenção.
2. **Egress contido:** o processo não consegue abrir ligações fora do scope autorizado, mesmo que o binário tente.
3. **Filesystem contido:** o processo não lê nem escreve estado do host fora de uma área efémera por execução.

Se uma destas propriedades não for demonstrável, o adapter fica fora do catálogo agentic. Pode continuar disponível nos fluxos normais de recon, mas não é seleccionável pelo modelo nem executável por `agent execute`/`agent cycle`.

O campo `AgentToolSpec.Isolation` nomeia o perfil de execução admitido. `Validate` rejeita qualquer perfil que ainda não tenha implementação e testes; hoje só aceita `native_in_process_metered`.

## Perfil admitido: `native_in_process_metered`

| Dimensão | Garantia |
|---|---|
| Egress | Cliente HTTP Go com `MeteredRoundTripper`; cada `RoundTrip` chama `ConsumeRequest` antes do transporte. |
| Redirects | Não seguidos (`CheckRedirect` recusa). |
| Corpos | Não recolhidos; o probe usa `HEAD` e fecha a resposta. |
| Retries | Nenhum; cada tentativa seria uma nova chamada ao meter. |
| Scope | `program_active_url`, revalidado no pedido e no ledger antes do débito. |
| Filesystem | Nenhum acesso; o adapter não abre ficheiros. |
| Processo | In-process; não inicia subprocesso nem shell. |
| Timeout/cancelamento | Contexto do chamador propagado ao transporte. |
| Recursos | Caps de targets, URL, outcomes e logs definidos no catálogo e normalizados. |
| Accounting | `one_request_per_target`; o budget do ledger cobre todos os targets. |
| Auditoria | `tool_version`, `profile_version`, outcomes por target e logs limitados, sem headers, bodies ou credenciais. |

Este perfil é suficiente para adapters nativos de baixo impacto. Não é extensível a binários externos: um subprocesso não herda o `MeteredRoundTripper`.

## Perfis implementados

Qualquer perfil exige implementação, testes negativos e actualização deste documento **antes** de aparecer em `AgentToolSpec`.

### `native_in_process_metered`

Perfil dos probes nativos `native_http_probe` e `native_tls_probe`, descritos acima. Não é extensível a binários externos.

### `subprocess_network_denied`

Implementado no núcleo `AgentExecRunner`, ainda não registado no catálogo. Para ferramentas locais revistas que não precisam de rede.

- **Contrato:** `AgentExecSpec` exige `Network = none` e `Filesystem = ephemeral_tmp`; qualquer outro valor é rejeitado por `Validate`.
- **Egress:** negado pelo sandbox do sistema. Em macOS, o perfil `sandbox-exec` aplica `(deny network*)`; em Linux, o `bubblewrap` usa `--unshare-net`. Se o sandbox não estiver disponível, `AgentExecRunner` devolve `ErrAgentExecSandboxUnavailable` e não inicia o processo. `sandbox-exec` está deprecated pela Apple; se for removido, o perfil deixa de estar disponível em macOS e o runner falha fechado.
- **Filesystem:** o processo corre num diretório efémero por execução; em macOS, `(deny file-write*)` só permite escritas nesse diretório e em `/dev/null`; em Linux, a raiz é montada read-only e só o diretório efémero é read-write. `HOME` e `TMPDIR` apontam para o diretório efémero e `PYTHONDONTWRITEBYTECODE=1` evita escritas de bytecode.
- **Leituras:** em macOS, os caminhos de credenciais comuns (`~/.ssh`, `~/.aws`, `~/.config`, `~/.docker`, `~/.gnupg`, `~/.kube`, `~/.heimdall`, `~/Library/Keychains`) são negados em leitura. Em Linux, a raiz read-only continua legível; binários revistos não podem receber caminhos de segredos. Esta é uma limitação conhecida do primeiro perfil.
- **Recursos:** `AgentExecSpec` já limita timeout, stdin, stdout e stderr; o runner mata o process group em timeout/cancelamento.
- **Accounting:** o perfil é apenas para ferramentas sem rede; não produz requests externos. Um adapter com este perfil não pode declarar targets de rede nem ser usado para recon ativo.
- **Auditoria:** `AgentExecResult.Sandbox` regista o sandbox usado (`sandbox-exec` ou `bubblewrap`); stdout/stderr ficam limitados e truncados.

### Perfis futuros

#### `subprocess_metered_proxy`

Para ferramentas que precisam de rede mas não podem ser reimplementadas em Go.

- **Egress:** a única rota é um proxy local obrigatório, no mesmo processo ou num processo supervisionado, que:
  - valida cada destino contra o scope activo do programa;
  - debita o ledger **antes** de encaminhar o pedido;
  - resolve DNS e recusa destinos fora do scope;
  - limita métodos, headers e tamanho de resposta.
- **Rede do processo:** restrita ao loopback do proxy por sandbox de rede. A ferramenta não pode abrir sockets directos; isto é imposto pelo sandbox, não assumido.
- **Accounting:** `one_request_per_target` quando o custo é conhecido, ou um tipo explícito de pior caso. O ledger reserva o pior caso antes do arranque; sobras são libertadas no fecho.
- **Proibido:** inferir requests a partir de stdout, logs ou contadores internos da ferramenta.
- **Kill switch:** o proxy fecha e o process group é morto quando o budget, a autorização ou o consentimento mudam.

## Critérios de admissão

Todos obrigatórios. Um adapter só entra no catálogo quando cada linha tem evidência no código e nos testes.

| # | Critério | Evidência exigida | Onde é imposto |
|---|---|---|---|
| 1 | Identidade e versão compiladas | `id` e `version` revistos; `origin = compiled` | `AgentToolSpec.Validate` |
| 2 | Classe de risco | `class = safe_active`, sem estado alterado | `AgentToolSpec.Validate` |
| 3 | Scope | `scope_rule = program_active_url` e validação por target | `Validate`, `AuthorizeTargets`, ledger |
| 4 | Accounting | meter injectado, débito antes do envio, teste com meter falso que falha | testes do adapter + ledger |
| 5 | Isolamento de egress | perfil implementado; teste negativo prova que o egress directo falha | sandbox + teste de integração |
| 6 | Isolamento de filesystem | root read-only e tmp efémero; teste tenta escrever fora e falha | sandbox + teste de integração |
| 7 | Limites de recursos | rlimits/timeout/caps aplicados e testados | runner + teste |
| 8 | Kill switch | timeout, cancelamento e revogação matam o process group | runner + teste |
| 9 | Auditoria | resultado normalizado, limitado e sem segredos | `NormalizeAgentCollection` + testes |
| 10 | Sem shell arbitrário | binário absoluto, `argv` fixo, allowlist exacta, sem `-c`/`--command` | `AgentExecSpec.Validate` + testes |

Um adapter que falhe um critério não é “parcialmente elegível”. Fica de fora até o critério estar cumprido.

## Falha fechada

- Perfil de isolamento desconhecido ou não implementado: `AgentToolSpec.Validate` rejeita o registo.
- Sandbox indisponível no host: o runner recusa iniciar o processo; não há execução “sem isolamento”.
- Meter ausente: o adapter devolve erro antes de qualquer request; `MeteredRoundTripper` falha sem meter.
- Ledger, autorização, consentimento ou scope alterados: o débito falha e nenhum request sai.
- Timeout/cancelamento: o process group é morto; o resultado é `failed` ou `uncertain` conforme o ledger, sem replay automático.
- Output acima do cap: truncado com flag explícita; nunca é guardado sem limite.

## Estado atual

| Perfil | Adapter | Estado |
|---|---|---|
| `native_in_process_metered` | `native_http_probe`, `native_tls_probe` | Implementado e elegível para ciclos autónomos. |
| `subprocess_network_denied` | nenhum | Implementado no núcleo `AgentExecRunner`; nenhum adapter registado. |
| `subprocess_metered_proxy` | nenhum | Não implementado. |
| Núcleo `AgentExecRunner` | não registado | Executa Go/Python/Shell com `argv` fixo, sem shell, process group, timeout/caps e sandbox obrigatório. Em macOS usa `sandbox-exec`; em Linux usa `bubblewrap` quando disponível; caso contrário falha fechado. Continua sem meter de requests porque só admite o perfil sem rede. |

O núcleo `AgentExecRunner` implementa o perfil `subprocess_network_denied`, mas não é, por si só, um adapter agentic. Registar um adapter exige ainda um schema de targets compatível com o catálogo, que hoje só expressa `http_url`/`program_active_url` e accounting `one_request_per_target`.

## Evidência mínima para admitir um novo perfil

- Testes unitários de validação e de falha fechada.
- Teste de integração em loopback com egress negativo (destino fora do scope recusado).
- Teste de isolamento de filesystem (escrita fora do tmp falha).
- Teste de timeout, cancelamento e kill do process group.
- Teste de accounting que prova o débito antes do envio e a ausência de contagem por stdout.
- `make check` verde, incluindo race tests e cobertura.
- Actualização de `roadmap/07`, `roadmap/21-estado-atual-e-gates.md` e `Development-roadmap.md`.

## Não-objectivos

- Este modelo não substitui o Policy Engine nem o ledger; complementa-os.
- Não valida findings nem autoriza exploração.
- Não permite shell arbitrário, comandos vindos de conteúdo de páginas, plugins, carregamento dinâmico ou ferramentas fornecidas implicitamente por MCP.
