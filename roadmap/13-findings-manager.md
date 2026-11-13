# Findings Manager e validação humana

Este componente será responsável por centralizar todas as descobertas produzidas pelo Heimdall.

É uma parte fundamental da arquitetura.

O objetivo é garantir que qualquer descoberta relevante seja registada, preservada, apresentada ao utilizador e acompanhada até à sua resolução.

O Findings Manager cobre **todas as descobertas** — ativos, endpoints, tecnologias, exposições e hipóteses — e não apenas vulnerabilidades. As vulnerabilidades são um subconjunto com campos e ciclo de validação próprios.

**O Heimdall deverá reportar as descobertas imediatamente. O utilizador deverá poder validar manualmente cada possível vulnerabilidade.**

## Tipos de descoberta

Nem todas as descobertas são vulnerabilidades.

O sistema deverá distinguir:

- Novo domínio.
- Novo subdomínio.
- Novo IP.
- Novo serviço.
- Nova aplicação.
- Nova tecnologia.
- Novo endpoint.
- Novo parâmetro.
- Novo ficheiro JavaScript.
- Possível exposição.
- Possível segredo.
- Comportamento suspeito.
- Possível vulnerabilidade.
- Vulnerabilidade confirmada.
- Alteração numa descoberta existente.

Todas as descobertas relevantes deverão ser registadas.

## Estrutura de uma Finding

Cada descoberta deverá possuir um identificador único.

Campos recomendados:

| Campo | Descrição |
|---|---|
| ID | Identificador único |
| Program | Programa associado |
| Target | Alvo associado |
| Title | Título |
| Description | Descrição |
| Category | Categoria |
| Severity | Severidade estimada |
| Impact | Impacto |
| Likelihood | Probabilidade |
| Confidence | Nível de confiança |
| Status | Estado atual |
| Asset | Ativo afetado |
| Endpoint | Endpoint associado |
| Parameters | Parâmetros relevantes |
| Source | Origem da descoberta |
| Method | Método ou ferramenta utilizada |
| Evidence | Evidências |
| Created At | Data de criação |
| Updated At | Data de atualização |
| Validated By | Responsável pela validação |
| Validation Notes | Observações |
| Resolution | Resultado final |

## Estados de uma descoberta

O ciclo de vida deverá distinguir claramente a descoberta da sua confirmação.

| Estado | Significado |
|---|---|
| `NEW` | Descoberta registada |
| `TRIAGED` | Classificada inicialmente |
| `NEEDS_VALIDATION` | Aguarda validação manual |
| `VALIDATING` | Em validação |
| `REPRODUCED` | Reproduzida por procedimento seguro e específico |
| `CONFIRMED` | Vulnerabilidade confirmada |
| `FALSE_POSITIVE` | Falso positivo |
| `INCONCLUSIVE` | Resultado inconclusivo |
| `NEEDS_INVESTIGATION` | Necessita de investigação adicional |
| `ACCEPTED_RISK` | Risco aceite |
| `CLOSED` | Encerrada |

Uma descoberta de ativo ou endpoint poderá ter um fluxo de estados diferente do fluxo de vulnerabilidades. O modelo deverá permitir essa distinção.

### Equivalência com a terminologia anterior

A versão anterior do roadmap usava uma nomenclatura distinta. Para compatibilidade:

| Estado canónico | Termo anterior |
|---|---|
| `NEW` | Hypothesis |
| `TRIAGED` | Suspected |
| `NEEDS_VALIDATION` | Awaiting Human Validation |
| `VALIDATING` | Evidence Collected |
| `REPRODUCED` | *(novo; sem equivalente direto)* |
| `CONFIRMED` | Confirmed |
| `FALSE_POSITIVE` | Rejected |
| `CLOSED` | Reported / Resolved |

`Reported` e `Resolved` passam a ser informação de resolução (`Resolution`) associada ao estado `CLOSED`, e não estados independentes.

`REPRODUCED` fica entre `VALIDATING` e `CONFIRMED`: existe reprodução controlada por um procedimento seguro e específico, mas ainda falta a confirmação humana final.

## Ciclo de evidência

O domínio de findings deverá ser independente da memória.

Estados de evidência:

1. `candidate` — saída de scanner ou hipótese, não confirmada.
2. `reproduced` — reproduzida por procedimento seguro e específico, com requests/respostas redigidas e ambiente/scope registados.
3. `validated` — evidência revista segundo os critérios do programa; nunca promoção automática por repetição ou resumo do modelo.
4. `rejected` / `needs_review` — falso positivo, resultado ambíguo ou evidência insuficiente.

Cada transição deverá registar:

- Programa e scope/source hash.
- Run e action IDs.
- Adapter e versão.
- Request budget usado.
- Timestamps.
- Nível de confiança.
- Operador/validador.
- Evidências associadas.

Resultados de Nuclei são sempre `candidate`/`finding_candidate`. Nenhum resultado de scanner ou de LLM pode ser promovido a `validated` sem reprodução e evidência.

## Evidências

Cada descoberta deverá manter as evidências que justificam a sua existência.

Possíveis evidências:

- Request HTTP.
- Response HTTP.
- Headers.
- Body.
- Screenshots.
- Browser traces.
- Logs.
- Output de ferramentas.
- Código JavaScript relevante.
- URLs.
- Parâmetros.
- Timestamps.
- Sequências de interação.
- Comparações entre contas de teste.
- Referências a endpoints.

As evidências originais deverão ser preservadas, sem depender exclusivamente do resumo produzido pelo modelo.

O Heimdall deverá guardar referências aos ficheiros e registos originais, permitindo consultar a fonte de cada conclusão.

Secrets, cookies, tokens e dados sensíveis deverão ser ocultados ou protegidos nos relatórios e notificações.

## Validação manual

O utilizador deverá conseguir analisar cada possível vulnerabilidade.

O processo deverá ser:

1. Heimdall encontra um comportamento suspeito.
2. Regista a descoberta.
3. Recolhe as evidências disponíveis.
4. Avalia severidade e confiança iniciais.
5. Envia uma notificação ao Discord.
6. O utilizador consulta o relatório.
7. O utilizador reproduz e valida manualmente o comportamento.
8. Regista o resultado.
9. O Heimdall atualiza o estado.
10. O conhecimento do alvo é atualizado.

A confirmação técnica deverá estar associada a evidências suficientes.

A decisão do utilizador deverá ser registada separadamente da avaliação automática do agente.

## Tipos de validação

O utilizador poderá classificar uma descoberta como:

- Confirmada.
- Falso positivo.
- Inconclusiva.
- Necessita de mais investigação.
- Risco aceite.
- Encerrada.

Deverá também poder adicionar:

- Notas.
- Evidências adicionais.
- Passos de reprodução.
- Impacto observado.
- Justificação da decisão.

## Feedback para o agente

A validação humana deverá alimentar o Target Knowledge Engine.

Exemplo:

```text
Finding:
  Possible IDOR

Initial Assessment:
  Confidence: Medium

Human Validation:
  Result: False Positive

Reason:
  Object-level authorization is enforced.

Knowledge Update:
  Endpoint behavior documented.
  Authorization mechanism recorded.
  Similar hypotheses may be evaluated with this context.
```

O agente deverá utilizar esta informação em investigações futuras.

A conclusão não deverá ser aplicada indiscriminadamente a todos os endpoints semelhantes.
