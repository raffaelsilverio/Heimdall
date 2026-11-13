# Providers, persistência e reporting

## Providers e integração com modelos

O Heimdall deverá suportar vários providers.

A integração deverá ser modular, permitindo adicionar modelos sem alterar o Agent Runtime.

### Providers iniciais

- OpenAI API.
- OpenCode Zen.

### Providers futuros

- Anthropic.
- Modelos locais.
- Outros serviços compatíveis.

### Provider Interface

Deverá existir uma interface comum para os providers.

Responsabilidades:

- Autenticação.
- Envio de mensagens.
- Gestão de contexto.
- Tool calling / Function Calling.
- Streaming.
- Respostas estruturadas.
- Normalização das respostas.
- Tratamento de erros.
- Gestão de limites.
- Informação de utilização e custos, quando disponibilizada.

A seleção de modelos não deverá ficar rigidamente associada a um único provider.

### Model Router

O Model Router deverá permitir selecionar modelos diferentes para tarefas diferentes.

| Tarefa | Critério |
|---|---|
| Planning | Capacidade de raciocínio |
| Recon analysis | Velocidade e custo |
| JavaScript analysis | Capacidade de análise de código |
| Vulnerability reasoning | Capacidade de raciocínio |
| Business logic analysis | Contexto e raciocínio |
| Report generation | Qualidade de escrita |

A seleção deverá considerar qualidade, latência, custo e disponibilidade.

## Persistence Layer

O conhecimento deverá ser persistente entre execuções.

A arquitetura de armazenamento deverá começar simples e evoluir quando existir necessidade real.

### SQLite

Recomendado para a primeira fase.

Utilização:

- Programs / Projetos.
- Targets / Alvos.
- Assets.
- Applications.
- Endpoints.
- Parâmetros e descobertas.
- Findings.
- Evidence metadata.
- Test accounts.
- Sessões e referências a credenciais.
- Execution history.
- Agent sessions.
- Configurations.
- Events.

### Evolução futura

Quando necessário:

- SQLite.
- FTS para pesquisa lexical.
- Archive/restore e supersessão.
- PostgreSQL, para maior volume de dados e utilização concorrente.
- Object Storage para evidências volumosas.
- Full-text search.
- Vector search e pesquisa semântica.
- Pesquisa por relações.
- Graph Database, quando as relações entre ativos, aplicações, endpoints, fluxos e vulnerabilidades justificarem essa complexidade.

Deverão ser considerados em object storage:

- Screenshots.
- Responses.
- JavaScript files.
- Logs.
- Relatórios.
- Artefactos de execução.

O Graph Database não deverá ser uma dependência inicial. A primeira versão deverá utilizar uma base relacional com relações bem definidas.

A prioridade será construir um modelo de dados consistente que permita evoluir a persistência posteriormente.

## Reporting Engine

O Reporting Engine deverá transformar os resultados das investigações em relatórios técnicos.

Tipos de relatório:

- Reconnaissance Report.
- Attack Surface Report.
- Endpoint Inventory.
- Technology Inventory.
- JavaScript Intelligence Report.
- Findings Report.
- Vulnerability Report.
- Business Logic Analysis.
- Executive Summary.

Formatos previstos:

- Markdown.
- HTML.
- PDF.
- JSON.

Os relatórios deverão incluir:

- Resumo executivo.
- Ativos investigados.
- Metodologia.
- Vulnerabilidades.
- Severidade.
- Impacto.
- Evidências.
- Passos de reprodução.
- Recomendações.
- Limitações.
- Estado de validação.

Cada relatório deverá distinguir:

- Informação observada.
- Hipóteses.
- Resultados de ferramentas.
- Descobertas validadas.
- Vulnerabilidades confirmadas.
- Falsos positivos.
- Limitações da investigação.

O sistema não deverá apresentar hipóteses como vulnerabilidades confirmadas.

Os relatórios deverão evitar a exposição desnecessária de credenciais e dados pessoais.

### Rastreabilidade e submissão

- Cada alegação de um relatório deve referenciar evidência existente.
- Relatórios podem ser redigidos pelo modelo, mas não podem inventar evidência nem elevar uma hipótese a confirmada.
- O relatório exportado deve ser rastreável até ao programa, scope, run, action e evidência.
- Por omissão, não deve conter segredos, cookies, tokens ou tráfego bruto.
- A submissão a HackerOne, Bugcrowd ou outra plataforma é sempre um passo humano confirmado; o Heimdall prepara o rascunho, não submete sozinho.
