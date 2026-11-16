# Roadmap de desenvolvimento

O desenvolvimento deverá ser incremental.

Não deverá ser criada toda a estrutura da arquitetura antes de existir uma necessidade concreta. Cada fase deverá produzir uma capacidade funcional antes de avançar para a seguinte.

A prioridade é construir uma base funcional e evoluir a partir dela.

## Fase 1 — Core e Providers

Objetivo: consolidar e estabilizar a aplicação Go existente.

- Rever a estrutura atual do projeto.
- Estruturar e consolidar a CLI com Cobra.
- Organizar a configuração.
- Consolidar a integração com OpenCode Zen.
- Implementar a integração com OpenAI.
- Criar uma interface comum para providers.
- Implementar logging.
- Implementar tratamento de erros.
- Criar estrutura básica de projetos e alvos.
- Estabelecer testes.

**Resultado esperado:** o Heimdall comunica com diferentes providers através de uma interface consistente e possui uma base de CLI/configuração estável.

## Fase 2 — Autonomous Agent Runtime

Objetivo: permitir que o modelo planeie e execute tarefas através de ferramentas.

- Implementar o ciclo do agente.
- Gerir mensagens, histórico e contexto.
- Implementar Function Calling / tool calling. *(Reclassificado para a Fase 3 em 2026-11-16, por depender do Tool Registry.)*
- Controlar iterações, timeouts e limites.
- Implementar cancelamento.
- Registar execuções.
- Integrar o Planner como capacidade do runtime.
- Dividir objetivos em tarefas, identificar dependências e replanear.
- Consultar conhecimento anterior e evitar tarefas redundantes.

**Resultado esperado:** um agente generalista consegue planear uma tarefa simples, executar ferramentas disponíveis e decidir os próximos passos dentro dos limites definidos.

## Fase 3 — Tool Registry e Execution Layer

Objetivo: criar uma infraestrutura consistente de ferramentas.

- Criar o Tool Registry.
- Implementar Function Calling / tool calling nativo com schemas do Registry.
- Definir schemas e metadados.
- Registar ferramentas.
- Validar argumentos.
- Implementar execução de processos.
- Suportar Go, Python e Shell.
- Aplicar timeouts e limites de recursos.
- Normalizar outputs.
- Preservar logs e auditoria.

**Resultado esperado:** o agente utiliza ferramentas externas através de uma camada controlada.

Integrar inicialmente poucas ferramentas.

## Fase 4 — Policy Engine e Program Intelligence

Objetivo: garantir que todas as operações respeitam as autorizações e exigências do programa.

- Implementar programas e targets.
- Implementar scope, allowlist e denylist.
- Configuração e regras por programa.
- Headers obrigatórios e User-Agent.
- Rate limits.
- Gestão de contas de teste.
- Restrição de acesso a dados de utilizadores.
- Aprovações.
- Validação de DNS e redirecionamentos.
- Request Policy Middleware.
- Criar auditoria das decisões.
- Definir níveis de impacto.

**Resultado esperado:** todas as operações passam por validação centralizada antes da execução.

Esta fase deve anteceder a execução autónoma de operações de segurança sobre alvos externos.

## Fase 5 — Browser Automation Engine

Objetivo: dar ao agente capacidade de interagir com aplicações web.

- Criar o Python Worker.
- Integrar Playwright.
- Implementar Browser Manager.
- Implementar Session Manager.
- Implementar Navigation Engine.
- Implementar Network Observer.
- Implementar DOM Inspector.
- Implementar JavaScript Inspector.
- Implementar Evidence Collector.
- Implementar Test Executor.
- Integrar políticas e headers obrigatórios.
- Associar sessões às contas de teste.
- Implementar Browser Handoff.

**Resultado esperado:** o agente consegue navegar, observar tráfego, recolher evidências e conduzir testes autorizados com sessões de contas de teste.

Começar com Chromium.

## Fase 6 — Reconnaissance Engine

Objetivo: implementar o primeiro pipeline completo de reconnaissance.

Ordem sugerida:

1. Subdomain Enumeration.
2. DNS Resolution.
3. HTTP Probing.
4. Technology Fingerprinting.
5. Historical URL Discovery.
6. Web Crawling.
7. JavaScript Intelligence.
8. Endpoint Discovery.
9. Parameter Discovery.
10. Content Discovery.
11. Public Exposure Intelligence.
12. Nuclei Integration.
13. Correlation.

**Resultado esperado:** o Heimdall mapeia uma superfície de ataque autorizada e produz resultados estruturados e reutilizáveis.

## Fase 7 — Target Knowledge Engine

Objetivo: construir a memória persistente dos alvos.

- Implementar SQLite.
- Criar modelo de dados, entidades e relações.
- Criar inventário de ativos e aplicações.
- Criar catálogo de endpoints e tecnologias.
- Guardar evidências, provenance e confidence.
- Implementar freshness e histórico.
- Implementar pesquisa.
- Implementar atualização automática.
- Integrar a memória com o Agent Runtime.

**Resultado esperado:** o agente recupera e reutiliza conhecimento de investigações anteriores.

## Fase 8 — Findings Manager e Human Validation

Objetivo: implementar o ciclo de descoberta e validação.

- Criar modelo de Finding.
- Definir categorias e tipos de descoberta.
- Definir estados e transições.
- Implementar severidade, impacto e confiança.
- Associar evidências.
- Implementar deduplicação.
- Criar histórico de validação.
- Permitir notas e decisões do utilizador.
- Atualizar o Target Knowledge após validação.
- Integrar relatórios.

**Resultado esperado:** todas as possíveis vulnerabilidades ficam registadas e podem ser acompanhadas até à conclusão.

## Fase 9 — Discord Integration

Objetivo: transformar o Discord no principal canal remoto de comunicação e supervisão.

- Criar Discord Bot.
- Implementar autenticação e allowlist.
- Integrar o Event System.
- Implementar Notification Service.
- Enviar notificações de descobertas.
- Implementar consulta de findings.
- Implementar ações de validação e notas.
- Implementar aprovações.
- Implementar Browser Handoff.
- Implementar estado dos agentes e pesquisa de memória.
- Criar auditoria das ações.
- Aplicar controlo de acesso.

**Resultado esperado:** o utilizador recebe notificações e gere o ciclo de validação pelo Discord sem depender do terminal.

## Fase 10 — Business Logic Intelligence

Objetivo: compreender o funcionamento das aplicações.

- Identificar e mapear fluxos.
- Mapear estados e transições.
- Identificar papéis e permissões.
- Identificar regras de negócio.
- Relacionar endpoints e dependências.
- Comparar comportamento entre contas de teste.
- Executar testes de autorização.
- Formular hipóteses de falhas lógicas.
- Atualizar a memória e apresentar evidências para validação manual.

**Resultado esperado:** o Heimdall deixa de analisar apenas endpoints isolados e começa a compreender o comportamento funcional das aplicações.

## Fase 11 — Multi-Agent Architecture

Objetivo: especializar a investigação.

- Recon Agent.
- JavaScript Agent.
- Web Security Agent.
- API Security Agent.
- Infrastructure Agent.
- Business Logic Agent.
- Authentication Agent.
- Vulnerability Agent.
- Reporting Agent.

Implementar coordenação e delegação entre agentes.

**Resultado esperado:** agentes especializados trabalham sob coordenação centralizada e as mesmas políticas.

## Fase 12 — TUI, benchmarks e melhoria contínua

- Implementar TUI.
- Implementar benchmarks e métricas.
- Evoluir para PostgreSQL quando necessário.
- Melhorar pesquisa e correlação.
- Implementar observabilidade e métricas de execução.
- Melhorar qualidade e eficiência dos agentes.
- Avaliar novos providers e ferramentas.
- Reduzir custo por investigação.

**Resultado esperado:** plataforma mais completa, observável, avaliada e preparada para utilização contínua.

## Trilha transversal — Operação em VPS

Não é uma fase numerada. Corre em paralelo desde que exista daemon e torna-se obrigatória antes de ativar autonomia real.

- Empacotar daemon e toolchain (Docker/Compose ou systemd).
- Utilizador não-root, volume `HEIMDALL_HOME` e root filesystem read-only.
- Healthcheck, restart, logs persistentes e rotação.
- Fixar versões de ferramentas e templates.
- Secret manager e rotação de credenciais.
- Egress-only; browser worker em loopback.
- Backups, teste de restore e retenção de artefactos.
- Métricas, alertas e dead-man's switch.
- Runbook de incidente, kill switch e rollback.

**Resultado esperado:** o Heimdall corre de forma reprodutível numa VPS, sobrevive a restarts e pode ser atualizado sem perder estado nem duplicar efeitos.

Detalhe em `23-operacao-e-deploy.md`.
