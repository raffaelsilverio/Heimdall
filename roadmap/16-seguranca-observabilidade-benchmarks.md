# Segurança interna, observabilidade e benchmarks

## Segurança interna do Heimdall

O próprio Heimdall deverá ser construído com segurança desde o início.

### Controlo de execução

- Validação centralizada de ferramentas.
- Isolamento de processos.
- Timeouts.
- Limites de recursos.
- Auditoria.
- Gestão de permissões.
- Cancelamento de operações.
- Nenhum shell arbitrário, script gerado pelo modelo, acesso implícito a `$HOME`, segredos, sockets locais ou rede.
- Qualquer capacidade executável declara ficheiros/rede permitidos, timeout, CPU/memória e política de saída.

### Proteção contra prompt injection

Conteúdo obtido de:

- Websites.
- APIs.
- Ficheiros.
- JavaScript.
- Documentação.
- Output de ferramentas.

Deverá ser tratado como informação não confiável.

O Heimdall deverá:

- Separar dados de instruções.
- Não executar instruções encontradas em conteúdo externo.
- Não permitir que conteúdo do alvo altere políticas.
- Validar todas as chamadas de ferramentas.
- Manter o Policy Engine independente dos agentes.

O agente não poderá interpretar instruções encontradas no alvo como autorização para modificar políticas, ignorar o âmbito ou executar comandos.

Por omissão, corpos brutos de respostas não são enviados ao modelo. O conteúdo deve ser redigido e delimitado como dado, nunca como instrução.

O workspace/code mode tem fronteiras próprias, descritas em `22-workspace-code-mode.md`.

### Gestão de secrets

Aplica-se a:

- API keys.
- Tokens.
- Cookies.
- Credenciais.
- Sessões.

Deverão ser armazenados de forma segura.

Não deverão ser expostos nos logs, no Discord ou nos relatórios.

### Segurança do Browser Worker

O Browser Worker deverá:

- Executar isoladamente.
- Utilizar contextos separados por sessão.
- Respeitar o âmbito autorizado.
- Aplicar requisitos HTTP do programa.
- Impedir fugas de credenciais entre origens.
- Registar operações.
- Controlar downloads e uploads.
- Limitar operações de impacto elevado.

### Segurança operacional (VPS e containers)

- Executar como utilizador não-root.
- Root filesystem read-only quando possível.
- Montar apenas o volume de dados (`HEIMDALL_HOME`).
- Sem portas de entrada; apenas egress necessário.
- Browser worker em container/processo separado, acessível apenas por loopback.
- Segredos em secret manager ou ambiente injetado, com rotação.
- Quotas de disco e retenção de artefactos e logs.
- Versões de binários e ferramentas fixadas, com rollback.
- Alertas para daemon parado, falhas repetidas e quota esgotada.

## Observabilidade e auditoria

O Heimdall deverá preservar o histórico das suas operações.

Informações importantes:

- Tarefa executada.
- Agente responsável.
- Modelo utilizado.
- Ferramenta utilizada.
- Argumentos relevantes.
- Alvo.
- Scope aplicado.
- Início e fim.
- Resultado.
- Erros.
- Aprovações.
- Decisões humanas.
- Alterações ao conhecimento.

A auditoria deverá permitir reconstruir como determinada descoberta foi produzida.

Tecnologias:

- Go `slog` para logging estruturado.
- Métricas de execução.
- OpenTelemetry como evolução futura.

Para operação contínua, deverão existir métricas de runs, falhas, fila, budgets e disco, alertas de daemon parado e um dead-man's switch externo.

## Benchmarks e avaliação

O Heimdall deverá ser avaliado de forma sistemática.

A qualidade não deverá ser medida apenas pelo número de vulnerabilidades encontradas.

### Ambientes de teste

- OWASP Juice Shop.
- DVWA.
- OWASP crAPI.
- PortSwigger Web Security Academy.
- Hack The Box.
- VulnHub.
- Laboratórios locais autorizados.

As avaliações deverão decorrer em ambientes próprios ou explicitamente autorizados.

### Métricas

**Reconnaissance**

- Subdomínios encontrados.
- Cobertura de ativos e de reconhecimento.
- Deduplicação.
- Precisão de HTTP probing.
- Endpoints identificados.
- Endpoints extraídos de JavaScript.
- Parâmetros encontrados.
- Qualidade da correlação.

**Knowledge Engine**

- Precisão das relações.
- Provenance.
- Atualização de informação.
- Reutilização de conhecimento e da memória.
- Deteção de alterações.
- Identificação de informação desatualizada.

**Findings**

- Precisão das hipóteses.
- Taxa de falsos positivos.
- Evidências disponíveis.
- Qualidade das classificações.
- Tempo até à validação.
- Taxa de validação.

**Agent Runtime**

- Seleção de ferramentas.
- Cumprimento dos planos.
- Qualidade do raciocínio.
- Gestão de contexto.
- Custo por investigação.
- Tempo de investigação.
- Custo de modelos.

**Discord**

- Latência de notificação.
- Perda de eventos.
- Deduplicação.
- Fiabilidade das ações.
- Integridade da auditoria.

**Policy Engine**

- Cumprimento do scope.
- Cumprimento das regras do programa.
- Bloqueio de operações não autorizadas.
- Aplicação correta de headers.
- Aplicação dos rate limits.
- Isolamento das contas de teste.
- Integridade das aprovações.
