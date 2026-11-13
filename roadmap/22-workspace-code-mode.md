# Workspace/Code mode

O Heimdall deverá evoluir para uma plataforma com dois modos de trabalho relacionados, mas isolados.

1. **Workspace/Code mode** — experiência iterativa de agente de código: compreender um repositório, localizar problemas, propor alterações, executar verificações permitidas e apresentar um diff revisável.
2. **Engagement/Security mode** — agente de bug bounty e pentest autorizado: planear e executar adapters registados, interpretar resultados, adaptar os próximos passos dentro de uma autorização e produzir achados com evidência.

O objetivo não é dar um terminal irrestrito ao modelo.

**O modelo propõe; o Heimdall valida contexto, política e limites; adapters compilados executam; o ledger registra a ação e a sua evidência.**

Os dois modos podem partilhar contratos e infraestrutura, mas **não partilham memória factual, permissões ou contexto**.

## Fronteiras de segurança

- O contexto de engagement está sempre vinculado a um `program_id`.
- O contexto de código está sempre vinculado a um `workspace_id` e a um checkout explícito.
- O workspace não herda factos de programas de bug bounty.
- Programas não recebem código privado sem egress consentido.
- Permissões de ficheiro e de rede são diferentes das permissões de engagement.
- Nenhuma alteração ao código de produção, exploração do sistema local ou acesso à rede acontece apenas porque o modelo pediu.

## Capacidades pretendidas

Todas registadas e tipadas:

- Listar ficheiros e procurar símbolos/texto dentro do workspace permitido.
- Ler ficheiros sob limite de tamanho e proteção contra symlink/path traversal.
- Gerar um patch revisável e aplicá-lo apenas ao workspace autorizado.
- Executar verificações por identificador fixo: testes, build e scanners aprovados.
- Apresentar diff, resultados e evidência para revisão.

Não existirá:

- Shell arbitrário.
- Scripts gerados pelo modelo.
- Acesso implícito a `$HOME`, segredos, sockets locais ou rede.

Uma capacidade de teste executável deve declarar ficheiros e rede permitidos, timeout, CPU/memória e política de saída.

## Fluxo de trabalho

```text
Inspecionar
    │
    ▼
Planear patch
    │
    ▼
Editar dentro do checkout
    │
    ▼
Executar verificações registadas
    │
    ▼
Rever diff
    │
    ▼
Aprovar
```

Nenhuma etapa de execução ou aplicação de patch pode ser saltada por decisão do agente.

## Sandbox de execução

- Limites de filesystem.
- Limites de processo.
- Limites de CPU e memória.
- Limites de rede.
- Timeout por operação.
- Saída controlada e auditada.

O sandbox é independente do sandbox de engagement e tem o seu próprio conjunto de permissões.

O sandbox corre em container/processo separado do daemon, sem acesso ao volume de engagement, às contas de teste ou às chaves dos providers.

## Verificações e formatos

Ferramentas estáticas registadas, entre outras:

- `go test`.
- `go vet`.
- Build.
- SAST.
- Deteção de secrets.
- Análise de dependências.
- Análise de IaC.

Formatos de saída:

- SARIF, onde aplicável.
- SBOM CycloneDX, onde aplicável.
- Diff unificado revisto pelo utilizador.

## Relação com o roadmap

O Workspace/Code mode é uma **trilha própria**, não uma das 12 fases de engagement.

Deverá entrar depois de estabilizados o Policy Engine (Fase 4) e o Tool Registry (Fase 3), reutilizando:

- O ledger e o accounting de operações.
- O modelo de permissões e aprovações.
- O Evidence Collector.
- O modelo de findings e de revisão.

Não deverá reutilizar a memória factual, as contas de teste nem o scope dos programas de bug bounty.

## Gates de aceite

Testes em repositórios de laboratório devem validar:

- Path traversal.
- Symlinks.
- Exposição de secrets.
- Patch incorreto.
- Comando fora da allowlist.
- Execução sem aprovação.
- Isolamento entre workspaces.
- Ausência de rede não declarada.

Nenhuma verificação de Workspace/Code mode deve correr contra programas reais em CI.
