# Target Knowledge Engine

O Target Knowledge Engine será o sistema responsável por preservar o conhecimento técnico de cada programa e alvo.

Esta funcionalidade será um dos maiores diferenciais do Heimdall.

O objetivo é permitir que o agente compreenda progressivamente as aplicações, infraestrutura, funcionalidades e relações entre os componentes de um alvo.

Não deverá ser necessário repetir toda a reconnaissance sempre que uma nova investigação começar.

O sistema não deverá depender exclusivamente do histórico de conversas com o modelo. Deverá existir uma base de conhecimento independente e consultável pelos agentes.

## Isolamento da memória

- A memória é estritamente isolada por `program_id` e por alvo.
- Briefings e resumos de memória são sempre same-program e filtrados por freshness.
- Não existe partilha de factos entre programas nem entre engagement e workspace.
- O workspace tem memória própria e não herda factos de bug bounty.
- A memória suporta pesquisa lexical/FTS, archive/restore e supersessão.
- A memória **nunca autoriza ações**. Uma nota antiga não substitui autorização, scope ou política atuais.

## Entidades

### Infraestrutura

- Program.
- Target.
- Domain.
- Subdomain.
- IP.
- Server.
- Service.
- Port.
- Certificate.
- Technology.

### Aplicação

- Application.
- API.
- Endpoint.
- Parameter.
- JS Asset.
- Page.
- Form.
- Component.

### Identidade e acesso

- User Account.
- User Role.
- Auth Mechanism.
- Session.
- Permission.
- Resource Ownership.

### Funcionamento da aplicação

- Business Flow.
- Business Rule.
- State Transition.
- Dependency.
- External Service.

### Segurança

- Vulnerability.
- Finding.
- Evidence.
- Test.
- Hypothesis.

## Relações

As entidades deverão estar relacionadas.

```text
Domain
  └── HOSTS → Subdomain
                   └── RESOLVES_TO → IP
                                        └── RUNS_ON → Server

Application
  ├── EXPOSES → Endpoint
  ├── USES → Technology
  ├── AUTHENTICATES_WITH → Auth Mechanism
  └── PARTICIPATES_IN → Business Flow

Endpoint
  ├── CALLS → API
  ├── REQUIRES → Auth Mechanism
  ├── USES → Parameter
  └── AFFECTS → Business Rule

Finding
  ├── AFFECTS → Endpoint
  ├── VALIDATED_BY → Evidence
  └── DISCOVERED_FROM → Reconnaissance Result
```

Relações adicionais a suportar:

- DEPENDS_ON.
- ALLOWS.
- OWNED_BY.
- ACCESSIBLE_BY.

## Provenance e confiança

Cada informação deverá preservar:

- Origem e fonte.
- Data de descoberta.
- Última atualização e última verificação.
- Método de recolha.
- Ferramenta utilizada.
- Evidência original.
- Nível de confiança.
- Estado de validação.
- Histórico de alterações.

O sistema deverá distinguir informação:

- Observada.
- Inferida.
- Validada.
- Desatualizada.
- Não confirmada.
- Contraditória.

Informações antigas não deverão ser simplesmente apagadas. Deverão ser marcadas como históricas ou desatualizadas, mantendo o histórico.

## Memória por alvo

Cada alvo deverá possuir conhecimento persistente e independente.

Exemplo:

```text
Program: Example Bug Bounty
Target: example.com

Applications:
  - Main Website
  - Customer Portal
  - Admin Portal

Technologies:
  - React
  - Django
  - PostgreSQL
  - Nginx

APIs:
  - api.example.com
  - internal-api.example.com

Authentication:
  - OAuth
  - JWT

Endpoints:
  - /api/users
  - /api/orders
  - /api/profile

Business Flows:
  - Registration
  - Login
  - Password Reset
  - Order Management

Findings:
  - Pending validation
  - Confirmed
  - False positives
```

O exemplo é ilustrativo.

Numa investigação seguinte, o Heimdall deverá consultar estes dados antes de iniciar um novo reconhecimento, identificar alterações, descobrir novos endpoints e evitar repetir operações desnecessárias.

A recuperação de memória não pode transportar factos de outro programa. Se o mesmo domínio aparecer em dois programas, os registos permanecem separados.

## Como o agente utiliza a memória

Antes de iniciar uma investigação, o agente deverá:

1. Consultar o programa e o alvo.
2. Recuperar ativos conhecidos.
3. Consultar endpoints e tecnologias.
4. Consultar descobertas anteriores.
5. Identificar lacunas de conhecimento.
6. Verificar informações desatualizadas.
7. Formular hipóteses.
8. Criar um plano baseado no conhecimento existente.

Depois de cada execução, deverá atualizar a memória com novas evidências.

## Conhecimento sobre contas de teste

A memória deverá preservar:

- Contas autorizadas.
- Papéis.
- Recursos de teste conhecidos.
- Relações de propriedade.
- Permissões observadas.
- Sessões.
- Resultados de testes de autorização.

Esta informação será essencial para investigações de IDOR, BOLA e controlo de acesso.

Não deverá armazenar dados pessoais de utilizadores reais desnecessariamente.

## Aprendizagem operacional

O sistema deverá conseguir aprender com:

- Resultados anteriores.
- Falsos positivos.
- Vulnerabilidades confirmadas.
- Métodos de validação.
- Ferramentas que produziram resultados úteis.
- Padrões específicos de uma aplicação.
- Relações entre endpoints.
- Alterações na infraestrutura.

Exemplo:

Se uma hipótese de IDOR for repetidamente classificada como falso positivo porque determinado endpoint utiliza um mecanismo específico de autorização, essa informação deverá ser preservada e utilizada para evitar investigações redundantes.

A memória não deverá transformar uma conclusão anterior numa regra universal. O agente deverá continuar a verificar o contexto e as evidências atuais.
