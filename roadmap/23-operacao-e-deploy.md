# Operação e deploy

Este documento descreve **como o Heimdall corre**, não o que faz.

Complementa `21-estado-atual-e-gates.md`: os gates dizem quando uma capacidade está pronta; este documento diz como a manter em execução.

## Modelo de operação

O Heimdall é um **serviço agendado**, não um agente sem supervisão.

- A descoberta, a triagem e a correlação podem ser autónomas.
- As ações são limitadas por política, consentimento, budgets e quotas.
- A confirmação de vulnerabilidades e a submissão de relatórios são humanas.

O processo principal é o daemon. A CLI serve para operação e inspeção; o Discord serve para supervisão remota.

## Topologia inicial

```text
VPS
├── heimdall daemon (Go)
│   ├── SQLite em HEIMDALL_HOME
│   ├── recon tools (versões fixas)
│   └── ledger / consentimentos / quotas
│
└── browser worker (container separado)
    └── Chromium + Playwright
        (acesso apenas por loopback)
```

Regras:

- Sem portas de entrada; apenas o egress necessário.
- O browser worker nunca fica exposto à Internet.
- Um único daemon escreve na base de dados; não correr dois daemons no mesmo `HEIMDALL_HOME`.
- A VPS é um ponto único de falha: assume-se e mitiga-se com restart, backups e alertas.

## Packaging

Uma das duas opções, não ambas:

- **Docker/Compose** para o daemon e para o browser worker.
- **systemd** com unit própria e `Restart=on-failure`.

Requisitos em qualquer opção:

- Utilizador não-root.
- Root filesystem read-only quando possível.
- Apenas o volume de dados (`HEIMDALL_HOME`) montado do host.
- `tmpfs` para temporários.
- Healthcheck que valide processo e base de dados **sem consumir jobs**.
- Encerramento gracioso por `SIGTERM`.
- Logs para stdout/journald com rotação.
- Browser worker em container/processo separado, sem acesso ao volume de engagement.

## Toolchain

- Fixar versões de Subfinder, Amass, dnsx, httpx, Naabu, Katana, gau, waybackurls, ffuf, Nuclei, Gitleaks, TruffleHog, Arjun, ParamSpider, jsluice, LinkFinder, Semgrep, Trivy.
- Registar as versões na imagem ou num manifesto verificável.
- Templates do Nuclei atualizados de forma controlada, com data e origem.
- Não permitir auto-update de ferramentas em runtime.
- Verificar binários e dependências no arranque; falhar cedo se faltarem.
- Fixar dependências Python do browser worker.

## Segredos

- Chaves de providers, token do Discord, tokens HackerOne e credenciais de contas de teste vêm de um secret manager ou de ambiente injetado.
- Nunca em imagens, repositório, argumentos de linha de comando ou logs.
- Rotação periódica e revogação imediata em caso de incidente.
- Segredos de engagement e de workspace ficam separados.
- O browser worker não recebe chaves de providers.

## Rede

- Egress-only; sem inbound.
- Allowlist de destinos quando possível.
- DNS e relógio sincronizados; quotas e leases usam UTC.
- Sem proxies de rotação ou mecanismos de evasão.
- O browser worker comunica com o core apenas por loopback.
- O IP da VPS pode ser bloqueado por programas; validar as regras antes de ativar.

## Dados, backups e retenção

- SQLite em modo WAL, com checkpoint controlado.
- Backup consistente antes de cada migração e em agenda diária.
- Testar restore periodicamente, não apenas o backup.
- Artefactos (screenshots, traces, respostas, logs) com retenção definida.
- Quota de disco com alerta; sem retenção, a VPS enche.
- Evidências que sustentam findings não devem ser eliminadas enquanto o finding estiver aberto.
- Object storage passa a fazer sentido quando o volume local deixar de ser confortável.

## Observabilidade

- Logs estruturados em JSON, com `run_id`, `program_id`, `action_id` e `adapter`.
- Métricas mínimas: runs, falhas, profundidade da fila, budgets consumidos, latência e disco.
- Alertas para daemon parado, falhas repetidas, quota esgotada e disco acima do limiar.
- **Dead-man's switch** externo: se a VPS desaparecer, o operador é notificado.
- Auditoria preservada; nunca registar segredos ou corpos brutos por omissão.

## Atualizações e migrações

1. Drenar: parar de aceitar novos jobs e deixar terminar o atual.
2. Fazer backup.
3. Aplicar o binário e as migrações.
4. Validar healthcheck e um ciclo controlado.
5. Retomar o daemon.

Regras:

- Migrações que alteram limites ou policy binding podem invalidar consentimentos antigos; o operador tem de os rever.
- Rollback exige binário anterior **e** backup compatível.
- Atualizações de ferramentas são versionadas e testadas offline.

## Capacidade e evolução

Ordem de grandeza para uma única VPS com browser:

- 2–4 vCPU e 4–8 GB de RAM, ajustado ao número de contextos de browser.
- 50–100 GB de disco, dependente da retenção de artefactos.
- Um daemon e um worker; concorrência limitada por programa.

Quando evoluir:

- Vários workers ou vários operadores → PostgreSQL e fila partilhada.
- Artefactos grandes → object storage.
- Alta disponibilidade → mais do que uma VPS e coordenação de leases.
- Nunca escalar através de rotação de IPs ou proxies.

## Runbook mínimo

- **Iniciar/parar/reiniciar:** daemon e worker de forma independente.
- **Kill switch:** revogar consentimentos, pausar programas e parar o daemon.
- **Incidente:** preservar logs e base de dados, revogar segredos, verificar scope e ações incertas.
- **Restore:** restaurar backup, validar migrações e confirmar que não há replay automático.
- **Autorização expirada:** confirmar que o programa foi pausado e que não houve requests.

## Critérios de pronto

Os gates operacionais canónicos estão em `21-estado-atual-e-gates.md`.

Antes de declarar o deploy pronto, confirmar em ambiente de teste:

- Restart e restore ensaiados, sem duplicação de efeitos.
- Métricas, alertas e dead-man's switch ativos.
- Runbook, kill switch e rollback revistos pelo operador.
- Nenhum segredo em logs, imagens ou exportações.
