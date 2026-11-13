# Interfaces

O Heimdall deverá possuir três interfaces principais: CLI, TUI e Discord.

Todas utilizam os mesmos serviços internos da Application Layer. Nenhuma interface executa operações diretamente: as ações passam pelo Orchestrator, pelo Tool Registry e pelo Policy Engine.

---

## CLI — Command Line Interface

A CLI será a interface principal durante o desenvolvimento inicial.

**Tecnologia:** Go + Cobra.

Responsabilidades:

- Criar e gerir programas e alvos.
- Executar tarefas de reconnaissance.
- Iniciar investigações.
- Consultar descobertas, vulnerabilidades e evidências.
- Gerir providers, agentes e configurações.
- Configurar políticas.
- Consultar o estado dos agentes e ferramentas.
- Gerar relatórios.

Exemplos conceptuais:

```bash
heimdall program create
heimdall target add example.com
heimdall recon start example.com
heimdall findings list
heimdall findings show <id>
heimdall report generate <program>
heimdall status
```

## TUI — Terminal User Interface

A TUI deverá proporcionar uma interface mais completa para utilização diária.

**Tecnologia:** Go + Bubble Tea.

Funcionalidades previstas:

- Dashboard de programas e alvos.
- Estado das investigações.
- Agentes ativos.
- Ferramentas em execução.
- Descobertas e vulnerabilidades em tempo real.
- Histórico de execuções e operações.
- Gestão de ferramentas.
- Visualização de evidências.
- Consulta do conhecimento acumulado.
- Aprovação de operações que exigem intervenção humana.

A TUI deverá ser desenvolvida depois de estabilizadas as funcionalidades fundamentais da CLI.

## Discord Bot

O Discord será o principal canal remoto de comunicação e supervisão, complementar à CLI e à TUI.

O utilizador deverá conseguir receber notificações, acompanhar investigações, consultar evidências e interagir com o sistema sem estar constantemente no terminal.

O Discord não será um sistema independente de execução. Será uma interface sobre a Application Layer do Heimdall, e não deverá executar comandos arbitrários de shell.

### Funcionalidades

**Gestão de programas e alvos**

- Criar e consultar programas.
- Adicionar e listar alvos.
- Consultar o scope e as regras do programa.
- Consultar o estado das investigações.

**Gestão de investigações**

- Iniciar reconnaissance.
- Consultar tarefas em execução e o estado dos agentes.
- Consultar resultados e histórico.
- Solicitar investigação adicional.

**Gestão de descobertas**

- Receber notificações imediatas.
- Consultar evidências.
- Validar manualmente possíveis vulnerabilidades.
- Classificar falsos positivos.
- Adicionar notas.
- Consultar descobertas pendentes.

**Gestão de conhecimento**

- Consultar endpoints, tecnologias, aplicações e APIs.
- Consultar fluxos de negócio.
- Consultar alterações na superfície de ataque.
- Pesquisar na memória do alvo.

**Aprovações**

- Listar operações pendentes.
- Aprovar ou rejeitar operações com âmbito, parâmetros e prazo definidos.

### Comandos conceptuais

```text
/programs
/program create

/targets
/target add
/target list
/target info

/recon start
/recon status

/findings
/findings list
/findings info
/finding <id>
/validate <id>
/confirm <id>
/false-positive <id>
/investigate <id>
/note <id>

/knowledge <target>
/memory search
/endpoints <target>
/technologies <target>
/flows <target>

/agent status
/approval list
/approval approve
/approval reject

/status
/report generate
```

A nomenclatura definitiva será definida durante a implementação.

A segurança do Discord (allowlist, RBAC, auditoria e separação entre notificação e execução) está detalhada em `14-discord.md`.
