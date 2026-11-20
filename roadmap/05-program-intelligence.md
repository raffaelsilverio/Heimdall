# Program Intelligence

Cada programa de Bug Bounty possui regras próprias, que determinam os ativos permitidos, os testes proibidos, os limites de requisições e os requisitos técnicos obrigatórios.

O Heimdall deverá compreender essas regras antes de iniciar qualquer investigação.

**As regras específicas do programa devem ser tratadas como requisitos operacionais obrigatórios, não como simples contexto enviado ao modelo.**

## Configuração por programa

Cada projeto deverá possuir uma configuração própria contendo:

- Nome do programa.
- Plataforma.
- Domínios e ativos autorizados.
- Scope tipado, incluindo portas e precedência de exclusão.
- Ativos excluídos.
- Schedules e limites de execução.
- Tipos de vulnerabilidade aceites.
- Tipos de testes proibidos.
- Limites de requisições.
- Regras de autenticação.
- Contas de teste autorizadas.
- Headers obrigatórios.
- User-Agent obrigatório, quando aplicável.
- Requisitos de identificação das requisições.
- Restrições relativas a dados de utilizadores.
- Regras para operações destrutivas.
- Requisitos de divulgação e reporte.
- Fonte das regras.
- Data da última verificação.
- Versão ou histórico das regras.

O sistema deverá permitir obter essas informações a partir de documentação fornecida pelo utilizador e, quando autorizado, de páginas públicas dos programas.

As regras extraídas automaticamente devem ser apresentadas como configurações verificáveis, com referência à sua origem.

## Sincronização com plataformas

Quando existir integração com plataformas de bug bounty:

- A sincronização deverá ser read-only e produzir snapshots das regras.
- Alterações de scope, autorização ou regras ficam em revisão pendente e podem pausar o programa.
- A aprovação de uma alteração nunca deverá reativar automaticamente um programa pausado.
- O scope/source hash é registado e revalidado antes de cada operação.
- Não deverá existir backfill de eventos anteriores ao consentimento.

## Hierarquia de políticas

O sistema deverá aplicar a seguinte hierarquia:

1. Leis e limites de segurança aplicáveis.
2. Regras e restrições da plataforma e do programa.
3. Âmbito e autorizações concedidas pelo utilizador.
4. Políticas gerais do Heimdall.
5. Plano de investigação do agente.

O agente não pode sobrepor-se a qualquer regra de nível superior.

Se existirem regras contraditórias, ambíguas ou incompletas, o sistema deverá bloquear a operação afetada e solicitar esclarecimento.

## Requisitos obrigatórios nas requisições HTTP

Alguns programas exigem que todas as requisições incluam um header específico.

Por exemplo:

`X-Bug-Bounty: researcher@example.com`

Ou:

`User-Agent: Heimdall-Security-Research/1.0`

O Heimdall deverá reconhecer esses requisitos e aplicá-los automaticamente.

A implementação deverá garantir que:

- Headers obrigatórios sejam adicionados a todas as requisições relevantes.
- O requisito seja aplicado independentemente da ferramenta utilizada.
- Requisições feitas pelo browser respeitem as mesmas exigências.
- Requisições HTTP diretas respeitem as mesmas exigências.
- Ferramentas externas recebam a configuração necessária.
- Headers sejam preservados durante o fluxo de execução quando permitido.
- Não sejam enviados headers sensíveis para domínios externos não autorizados.
- Redirecionamentos para outros domínios sejam novamente validados.
- O sistema consiga verificar se os requisitos foram efetivamente aplicados.

Não basta colocar essa instrução no prompt do agente. O cumprimento deve ser garantido tecnicamente pelo sistema de execução.

### Request Policy Middleware

Deverá existir uma camada central para aplicar e validar requisitos HTTP.

Responsabilidades:

- Configurar headers obrigatórios.
- Definir User-Agent.
- Aplicar regras específicas por domínio.
- Aplicar limites de frequência.
- Validar destinos.
- Controlar redirecionamentos.
- Impedir exposição de cookies e tokens.
- Registar metadados das requisições.
- Verificar requisitos específicos do programa.

Esta camada deverá ser integrada com o Browser Engine, clientes HTTP internos e adaptadores de ferramentas externas.

Quando uma ferramenta externa não permitir garantir um requisito obrigatório, o Heimdall não deverá executá-la até existir uma forma segura de assegurar o cumprimento.

## Exemplo de configuração

```yaml
program:
  name: Example Bug Bounty
  platform: HackerOne

  scope:
    allow:
      - "*.example.com"
      - "api.example.com"

    deny:
      - "staging.example.com"

  request_policy:
    headers:
      X-Bug-Bounty: "1silverio@example.com"

    user_agent: "1silverio"

    rate_limit:
      requests_per_second: 2

  accounts:
    mode: owned_or_explicitly_authorized
    users:
      - id: test-user-1
        role: user
      - id: test-user-2
        role: administrator

  data_access:
    allow_owned_test_accounts: true
    allow_explicitly_authorized_accounts: true
    allow_other_users_data: false
```

O exemplo é ilustrativo. Os valores reais deverão ser obtidos das regras do programa e das autorizações do utilizador.

O perfil de request é configurável por programa com `heimdall program request-profile set`: o `user_agent` e os `headers` são normalizados, ordenados e aplicados pelo middleware a pedidos HTTP nativos e ao estágio web. Headers de framing (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, etc.) e credenciais (`Authorization`, `Proxy-Authorization`, `Cookie`) são rejeitados; contas de teste e credenciais usam um mecanismo separado.

## Default: investigação apenas com contas de teste

O comportamento padrão do Heimdall deverá ser restritivo relativamente aos dados dos utilizadores.

**O agente só deverá consultar, manipular ou utilizar dados pertencentes às contas de teste criadas pelo utilizador ou expressamente autorizadas por ele.**

Isto deverá ser uma política global, aplicada a todos os agentes e ferramentas.

Por padrão:

- O agente deverá utilizar exclusivamente contas de teste conhecidas.
- Deverá conhecer a identidade e o papel de cada conta.
- Deverá distinguir contas de utilizador, administrador e outros perfis.
- Deverá associar sessões e tokens às respetivas contas.
- Deverá evitar aceder a recursos pertencentes a utilizadores reais.
- Não deverá enumerar identificadores de utilizadores reais para procurar dados.
- Não deverá considerar um recurso autorizado apenas porque a aplicação permite aceder-lhe.
- Não deverá utilizar dados pessoais de terceiros como evidência.
- Não deverá modificar dados de terceiros.

### Testes de autorização e IDOR

A existência desta restrição não impede a investigação de vulnerabilidades de autorização.

O agente poderá comparar o comportamento de duas ou mais contas de teste autorizadas.

Exemplo:

- Conta A: utilizador normal.
- Conta B: segundo utilizador de teste.
- Conta C: administrador de teste.

O agente poderá verificar:

- Se a Conta A consegue consultar recursos da própria conta.
- Se a Conta A consegue consultar recursos da Conta B.
- Se a Conta A consegue executar operações reservadas à Conta C.
- Se existem diferenças de autorização entre os perfis.
- Se a aplicação aplica corretamente as regras de propriedade dos recursos.

A comparação deverá utilizar recursos pertencentes às contas de teste.

Se for necessário investigar um cenário que envolva dados de terceiros, o agente deverá parar e solicitar autorização explícita e específica, confirmando que as regras do programa permitem esse procedimento. Mesmo com autorização, deverá minimizar o acesso e evitar recolher ou conservar dados pessoais desnecessários.

### Gestão de contas de teste

O Heimdall deverá manter um registo das contas autorizadas:

- Identificador interno.
- Projeto associado.
- Identidade da conta na aplicação.
- Papel ou permissões.
- Estado de autorização.
- Método de autenticação.
- Sessões associadas.
- Recursos de teste conhecidos.

Credenciais, cookies e tokens deverão ser armazenados de forma segura e nunca enviados em notificações Discord ou incluídos diretamente nos logs.

A criação de contas pelo agente só poderá ocorrer quando o utilizador a autorizar e as regras do programa permitirem.
