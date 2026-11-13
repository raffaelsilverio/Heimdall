# Discord Notification Service

O Discord será o principal canal remoto de comunicação entre o Heimdall e o utilizador, complementar à CLI e à TUI.

A integração deverá ser orientada a eventos, para que diferentes componentes possam comunicar descobertas sem depender diretamente da implementação do bot.

## Event System

Os componentes deverão produzir eventos internos.

Exemplos:

```text
TargetDiscovered
SubdomainDiscovered
ServiceDiscovered
TechnologyIdentified
EndpointDiscovered
JavaScriptAssetDiscovered
ParameterDiscovered
ExposureDetected
PossibleVulnerabilityDetected
FindingUpdated
FindingConfirmed
FalsePositiveRecorded
ValidationRequested
ScanStarted
ScanCompleted
ScanFailed
ApprovalRequired
KnowledgeUpdated
```

O Notification Service deverá subscrever os eventos relevantes.

Desta forma, novas ferramentas e agentes poderão gerar notificações sem implementar integrações específicas com o Discord.

## Notificações imediatas

Sempre que o Heimdall encontrar algo relevante, deverá criar ou atualizar o registo correspondente e notificar o utilizador.

O sistema deverá notificar quando:

- Um novo domínio, subdomínio ou serviço for descoberto.
- Uma nova aplicação for identificada.
- Um novo endpoint for encontrado.
- Um novo ficheiro JavaScript for analisado.
- Um novo fluxo de negócio for descoberto.
- Uma possível exposição for detetada.
- Uma hipótese de vulnerabilidade for criada.
- Uma vulnerabilidade for confirmada.
- Uma operação necessitar de aprovação.
- Uma sessão necessitar de validação humana (Browser Handoff).
- Uma investigação for concluída.

As notificações deverão incluir:

- Tipo de descoberta.
- Programa.
- Alvo.
- Descrição.
- Severidade estimada, quando aplicável.
- Nível de confiança.
- Origem da descoberta.
- Evidências principais.
- Identificador da Finding.
- Link ou referência para consultar os detalhes.

### Exemplo: possível vulnerabilidade

```text
HEIMDALL — POSSIBLE VULNERABILITY

Title: Possible IDOR
Target: example.com
Endpoint: GET /api/users/{id}

Severity: Medium
Confidence: Medium
Status: NEEDS_VALIDATION

Observation:
The endpoint appears to return object data
based on a user-controlled identifier.

Evidence:
- HTTP request
- HTTP response
- Endpoint source: JavaScript analysis
- Authentication required

Manual validation required.

Finding ID: F-00042
```

Este alerta representa uma hipótese, não uma confirmação.

### Exemplo: novo endpoint

```text
HEIMDALL — NEW ENDPOINT

Target: example.com
Endpoint: /api/orders
Method: GET

Source: JavaScript Intelligence
Application: Customer Portal

Status: Observed
Finding ID: D-00125
```

### Exemplo: nova tecnologia

```text
HEIMDALL — TECHNOLOGY DISCOVERED

Target: example.com
Technology: Django
Source: HTTP Fingerprinting

New technology associated with:
customer.example.com
```

## Deduplicação de notificações

O sistema não deverá enviar alertas repetidos para a mesma descoberta sem alterações relevantes.

Deverá:

- Identificar descobertas duplicadas.
- Atualizar o registo existente.
- Preservar novas evidências.
- Notificar quando houver alterações significativas.
- Evitar repetir notificações sem informação adicional.

Uma nova evidência relevante deverá poder gerar uma atualização do alerta original.

## Níveis de prioridade

O sistema deverá diferenciar notificações por importância.

| Prioridade | Exemplos | Comportamento |
|---|---|---|
| Crítica | Possível exposição de alto impacto | Notificação imediata prioritária |
| Alta | Possível vulnerabilidade relevante | Notificação imediata |
| Média | Endpoint ou comportamento suspeito | Notificação normal |
| Baixa | Informação técnica ou alteração menor | Notificação agrupada quando apropriado |
| Informativa | Atividade e estado de execução | Canal de atividade |

A prioridade não deverá ser confundida com severidade CVSS ou confirmação técnica.

## Interação através do Discord

A lista completa de comandos está definida em `02-interfaces.md`. As ações de notificação usam os mesmos comandos de consulta, validação e aprovação da Application Layer.

O utilizador deverá conseguir consultar uma descoberta sem precisar de regressar ao terminal.

## Botões de ação

As notificações poderão apresentar botões:

- View Details.
- Validate.
- Confirm.
- False Positive.
- Investigate.
- Add Note.

Os botões deverão executar operações da Application Layer, não comandos arbitrários de shell.

Uma ação de confirmação deverá guardar a decisão do utilizador, as evidências e a justificação. Não deverá substituir os requisitos de comprovação técnica.

## Aprovações

As operações que exigem autorização explícita, o âmbito da aprovação e os seus limites estão definidos em `06-policy-engine.md`.

O Discord apresenta o pedido, lista as aprovações pendentes e submete a decisão do utilizador à Application Layer. A aprovação nunca deve ser genérica nem ilimitada.

## Browser Handoff

O Discord deverá suportar o pedido de handoff descrito em `10-browser-automation.md`: o utilizador é notificado de que existe uma sessão de teste pronta para inspeção, mas credenciais e cookies nunca são enviados pela plataforma.

## Segurança do Discord

Deverá existir:

- Allowlist de utilizadores.
- RBAC.
- Verificação de permissões.
- Auditoria das ações.
- Validação de parâmetros.
- Gestão segura de tokens.
- Separação entre notificações e execução.
- Proteção contra comandos não autorizados.

Credenciais, cookies e tokens nunca deverão ser enviados diretamente através do Discord nem incluídos nos logs.
