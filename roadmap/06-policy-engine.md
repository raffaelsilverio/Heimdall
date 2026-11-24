# Policy Engine e Scope Management

A segurança operacional deverá estar centralizada no Policy Engine.

O sistema deverá operar exclusivamente sobre alvos autorizados.

O Policy Engine deverá funcionar independentemente do agente. Nenhum agente poderá ignorar ou substituir as suas decisões.

## Scope Management

Cada programa deverá possuir:

- Allowed domains.
- Allowed subdomains.
- Allowed IP ranges e portas, quando aplicável.
- Excluded assets.
- Excluded paths, quando aplicável.
- Precedência entre regras de inclusão e exclusão.
- Allowed testing methods.
- Rate limits.
- Schedules e janelas de execução.
- Restrictions.
- Program notes.

A configuração detalhada das regras do programa está descrita em `05-program-intelligence.md`.

## Validação

Antes de executar qualquer ferramenta, o sistema deverá:

1. Validar o alvo.
2. Consultar o scope.
3. Verificar exclusões.
4. Validar redirects.
5. Validar relações DNS e CNAME relevantes.
6. Aplicar limites de velocidade.
7. Verificar permissões.
8. Solicitar aprovação quando necessário.

O Policy Engine deverá verificar:

1. O alvo pertence ao âmbito autorizado?
2. O destino está permitido?
3. A operação é permitida pelo programa?
4. Os headers e requisitos obrigatórios estão configurados?
5. O limite de frequência será respeitado?
6. A conta utilizada está autorizada?
7. Os dados consultados pertencem a uma conta de teste autorizada?
8. A operação exige aprovação humana?
9. A ferramenta consegue cumprir as políticas?

A validação deverá ocorrer antes da execução, não apenas quando os resultados forem recolhidos.

O resultado deverá ser uma decisão explícita:

- `ALLOW`
- `DENY`
- `REQUIRE_APPROVAL`

## Request Policy Middleware

O perfil de request de cada programa é uma barreira independente aplicada imediatamente antes do envio:

- `User-Agent` obrigatório, com valor por omissão estável e revisão por programa.
- Headers obrigatórios normalizados e ordenados de forma determinística.
- Rejeição de headers de framing e de credenciais que o transporte ou o mecanismo de contas de teste devem controlar.
- Rejeição de nomes inválidos, duplicados, valores vazios, CR/LF, bytes não imprimíveis e limites excedidos.
- Aplicação a pedidos HTTP nativos e a todos os estágios que enviam HTTP (web, crawl, ffuf e nuclei); o handshake TLS não envia headers HTTP.
- O perfil é lido do store antes de cada ação e a revisão é persistida no resultado da ação; valores de headers nunca são registados em logs. Uma configuração inválida falha fechada antes do primeiro pedido.

## Data Access

O acesso a dados é uma política independente por programa:

- Modo único `test_accounts_only`; `allow_other_users_data` é sempre falso e não pode ser ativado por CLI.
- O registo de contas guarda identidade, papel, origem (`owned` ou `explicitly_authorized`) e estado (`authorized`/`revoked`).
- Apenas referências `env:NAME` são persistidas; o valor da credencial nunca entra na base de dados, na CLI ou nos logs. A resolução do segredo acontece na futura camada de sessão.
- Revogar uma conta mantém o registo para auditoria e impede a sua utilização.
- `DataAccessPolicy.AuthorizeTestAccount` valida a política, o estado e a origem; uma conta revogada ou uma fonte desativada falham fechado.
- A ausência de uma conta registada nunca é interpretada como autorização implícita.

## Controlo de impacto

As ferramentas deverão ser classificadas por nível de impacto.

Exemplos:

- Passive.
- Low Impact.
- Active.
- High Impact.

Operações de maior impacto deverão exigir aprovação explícita quando definido pela política do programa.

A aprovação deverá estar associada a:

- Operação concreta.
- Alvo.
- Parâmetros.
- Scope.
- Nível de impacto.
- Prazo de validade.

Não deverá existir aprovação genérica que permita ao agente executar operações ilimitadas.

O sistema não deverá contornar rate limits, bloqueios ou restrições dos programas através de rotação de proxies ou outros mecanismos de evasão.

## Separação de responsabilidades

O Policy Engine não é um componente do agente: é uma barreira independente entre a intenção do agente e a execução real.

- O agente propõe a operação.
- O Policy Engine decide.
- O Tool Registry verifica a compatibilidade da ferramenta com a decisão.
- A Execution Layer aplica a operação e registra o resultado.

A proteção contra conteúdo não confiável (prompt injection) é tratada em `16-seguranca-observabilidade-benchmarks.md`.

## Ledger e contabilização de requests

Nenhuma operação com efeito externo deverá existir apenas em memória ou em logs informais.

Deverá existir um ledger durável de action runs com:

- Reservas idempotentes antes da execução.
- Budgets de ação e de request por programa.
- Revalidação just-in-time de autorização, consentimento, policy revision e scope antes de cada ação e de cada request.
- Accounting por tentativa HTTP, incluindo tentativas falhadas e redirects.
- Registo de crash/resultado `uncertain` sem replay automático.
- Revisão auditada e resultado estruturado por ação.

Cada request deve ser debitado **antes** do envio, e ficar ligado a policy revision, programa, scope, run, action e adapter.

Um crash nunca pode repetir silenciosamente um efeito externo incerto. A repetição exige decisão explícita do operador.

Além dos budgets e quotas, existe um kill switch global e durável, independente de qualquer programa ou policy. Engatá-lo exige operador e motivo, fica auditado com uma revisão monotónica e interrompe criação, reserva, início e accounting de ações, o lease de ciclos adaptativos e o claim de runs agendados; runs já em lease falham a revalidação just-in-time. Soltá-lo também exige operador e motivo, e nunca acontece implicitamente por ausência de estado.

## Consentimento e limites operacionais

- O consentimento para ciclos autónomos é persistente, revisto e específico por programa.
- Programas e consentimentos novos ficam desabilitados por omissão.
- Apenas eventos materiais novos, criados com o consentimento ativo, podem gerar ciclos.
- Existem quotas de ciclos e requests reservadas atomicamente.
- Jobs e ações expirados não são repetidos automaticamente.
- O sistema falha fechado (`deny-by-default`) quando não consegue provar que a operação é permitida.

Deverão existir limites explícitos de duração total e de concorrência por programa, além de um kill switch observável.

O modelo de ação por programa é deny-by-default: sem autorização atual e política compatível, a decisão é `DENY`.
