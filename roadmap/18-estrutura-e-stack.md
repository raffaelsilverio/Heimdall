# Estrutura de diretórios e stack tecnológica

## Estrutura de diretórios proposta

A estrutura deverá evoluir progressivamente.

Não é necessário criar todos os diretórios no início.

Uma estrutura de referência para a evolução do projeto:

```text
Heimdall/
│
├── cmd/
│   └── heimdall/
│
├── internal/
│   ├── app/
│   ├── agent/
│   ├── orchestrator/
│   ├── providers/
│   ├── tools/
│   ├── execution/
│   ├── policy/
│   ├── recon/
│   ├── knowledge/
│   ├── findings/
│   ├── validation/
│   ├── notifications/
│   ├── discord/
│   ├── reporting/
│   └── storage/
│
├── browser/          # Python Worker (Playwright)
│   ├── manager/
│   ├── sessions/
│   └── collectors/
│
├── deploy/
│   ├── Dockerfile
│   ├── compose.yaml
│   └── systemd/
│
├── configs/
│
├── migrations/
│
├── tests/
│
├── docs/
│
├── go.mod
└── main.go
```

Esta estrutura é uma referência arquitetural, não uma instrução para criar tudo imediatamente.

A implementação deverá respeitar o estado atual do repositório.

## Topologia de execução

A primeira topologia é uma **única VPS**:

- Um daemon Go, um escritor SQLite e a toolchain de recon.
- Browser worker separado, acessível apenas por loopback.
- Apenas egress; nenhuma porta de entrada.

Limites aceites nesta fase:

- SQLite com um único escritor; não correr dois daemons no mesmo `HEIMDALL_HOME`.
- Sem alta disponibilidade: a VPS é um ponto único de falha.
- Backups, healthcheck e alertas são obrigatórios, não opcionais.

Evolução:

- Vários workers ou operadores → PostgreSQL e fila partilhada.
- Artefactos grandes → object storage.
- Alta disponibilidade → várias VPS com coordenação de leases.

Nunca se escala através de rotação de IPs ou proxies.

## Stack tecnológica

| Componente | Tecnologia |
|---|---|
| Linguagem principal / Core | Go |
| CLI | Cobra |
| TUI | Bubble Tea |
| Configuração | Viper |
| Logging | slog |
| Browser Worker | Python |
| Browser Automation | Playwright |
| Browser inicial | Chromium |
| Comunicação Core/Worker | JSON + HTTP local |
| Providers | OpenAI, OpenCode Zen, Anthropic, modelos locais |
| Agent Runtime | Implementação própria |
| Tool Integration | Function Calling e MCP |
| Execução | Processos externos controlados |
| Persistência inicial | SQLite |
| Persistência futura | PostgreSQL |
| Comunicação externa | Discord Bot API |
| Observabilidade | slog; métricas; OpenTelemetry futuro |
| Containers | Docker (daemon e browser worker isolados) |
| Deploy inicial | Docker Compose ou systemd numa única VPS |
| Testes | Go testing |

## Decisões técnicas

A arquitetura deverá privilegiar simplicidade, modularidade e facilidade de manutenção.

Decisões estruturais:

- O Core é escrito em Go; o browser worker é uma aplicação Python separada.
- O agente propõe operações; o Policy Engine valida; a Execution Layer executa.
- O browser é acedido apenas através do Tool Registry.
- A memória é independente do histórico de conversas com o modelo.
- As regras do programa são requisitos técnicos, não contexto de prompt.
- A persistência começa relacional e evolui apenas quando houver necessidade real.
- Nenhuma abstração é criada antecipadamente sem uma necessidade concreta.
