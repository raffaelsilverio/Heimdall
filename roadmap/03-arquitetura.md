# Arquitetura geral

A arquitetura deverá separar interfaces, coordenação, inteligência artificial, execução de ferramentas, políticas de segurança e persistência.

## Visão arquitetural

```text
                  INTERFACES
        ┌──────────┬──────────┬──────────┐
        │   CLI    │   TUI    │ Discord  │
        └──────────┴──────────┴──────────┘
                       │
                       ▼
               APPLICATION LAYER
          ┌─────────────────────────┐
          │ Commands / Events / API │
          └─────────────────────────┘
                       │
                       ▼
                  ORCHESTRATOR
          ┌─────────────────────────┐
          │ Planner                 │
          │ Agent Runtime           │
          │ Workflow Engine         │
          │ Model Router            │
          └─────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       RECON       KNOWLEDGE      FINDINGS
       ENGINE       ENGINE        MANAGER
          │            │            │
          └────────────┼────────────┘
                       │
                       ▼
                POLICY ENGINE
                       │
                       ▼
                 TOOL REGISTRY
                       │
                       ▼
               EXECUTION LAYER
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       CLI Tools     MCP Tools    Integrations
          │            │            │
          └────────────┼────────────┘
                       │
                       ▼
                 DATA LAYER
          ┌─────────────────────────┐
          │ Target Knowledge        │
          │ Evidence Store          │
          │ Findings                │
          │ Execution History       │
          │ Configuration           │
          └─────────────────────────┘
```

O Browser Automation Engine integra-se na Execution Layer, através do Tool Registry, mantendo-se separado do Agent Runtime.

## Componentes principais

### Application Layer

Responsável por disponibilizar as funcionalidades do Heimdall às diferentes interfaces.

Deverá centralizar:

- Commands.
- Events.
- Application Services.
- User Context.
- Permissions.
- Workflows independentes de interface.

A CLI, a TUI e o Discord deverão utilizar os mesmos serviços internos.

### Orchestrator

Responsável pela coordenação geral das investigações.

Deverá:

- Receber objetivos.
- Consultar o estado do alvo.
- Criar planos de investigação.
- Distribuir tarefas.
- Coordenar agentes.
- Gerir execuções.
- Recolher resultados.
- Atualizar o conhecimento.
- Encaminhar descobertas para o Findings Manager.

### Planner

O Planner é uma capacidade do Agent Runtime, não um serviço autónomo com ciclo de vida próprio.

Transforma objetivos em tarefas executáveis. Exemplo:

Objetivo: investigar a superfície de ataque de uma aplicação.

Plano possível:

1. Consultar o scope.
2. Recuperar conhecimento existente.
3. Identificar subdomínios conhecidos.
4. Procurar novos subdomínios.
5. Resolver DNS.
6. Identificar serviços HTTP.
7. Identificar tecnologias.
8. Recolher URLs históricas.
9. Analisar JavaScript.
10. Descobrir endpoints e parâmetros.
11. Correlacionar resultados.
12. Atualizar o conhecimento.
13. Reportar novas descobertas.

O Planner deverá considerar resultados anteriores e evitar repetir tarefas desnecessárias.

### Agent Runtime

Responsável pela execução dos agentes de IA e pelo ciclo de planeamento, decisão e utilização de ferramentas. Detalhado em `04-agent-runtime.md`.

### Model Router

Seleciona o provider e o modelo apropriados para cada tarefa, com base em capacidade, custo, latência e disponibilidade. Detalhado em `15-providers-persistencia-reporting.md`.

### Policy Engine

Centraliza as regras de autorização e execução.

Nenhum agente deverá conseguir contornar este componente para executar ferramentas. Detalhado em `06-policy-engine.md`.

### Tool Registry

Regista todas as ferramentas disponíveis e respetivas características. Detalhado em `07-tool-registry-e-execution.md`.

### Execution Layer

Executa ferramentas de forma controlada e recolhe resultados estruturados.

### Knowledge Engine

Mantém o conhecimento técnico persistente dos alvos. Detalhado em `11-target-knowledge.md`.

### Findings Manager

Centraliza descobertas, hipóteses, evidências e o ciclo de validação humana. Detalhado em `13-findings-manager.md`.

### Discord Notification Service

Distribui notificações e permite interação com o utilizador. Detalhado em `14-discord.md`.

## Coordenação e fluxo de execução

Os agentes não deverão comunicar diretamente com ferramentas sem passar pelos mecanismos centrais.

```text
Orchestrator
    │
    ▼
Agent
    │
    ▼
Tool Request
    │
    ▼
Policy Engine
    │
    ▼
Tool Registry
    │
    ▼
Execution Layer
    │
    ▼
Tool Result
    │
    ▼
Agent
    │
    ▼
Finding Manager / Knowledge Engine
```

O Orchestrator deverá controlar as tarefas, o contexto e as permissões.

O Discord, tal como as restantes interfaces, comunica com o Orchestrator; não executa diretamente comandos no terminal nem contorna o Policy Engine.
