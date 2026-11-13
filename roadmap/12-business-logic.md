# Business Logic Intelligence

A análise de lógica de negócio deverá ser uma capacidade importante do Heimdall.

Muitas vulnerabilidades não resultam de configurações incorretas ou falhas isoladas. Resultam de comportamentos inesperados na interação entre funcionalidades, estados, utilizadores e regras de negócio.

O sistema deverá tentar compreender como a aplicação funciona, e não apenas analisar endpoints isolados.

## Fluxos a identificar

Exemplos:

- Registration.
- Login.
- Password Reset.
- Account Recovery.
- Account Management.
- User Management.
- Orders.
- Payments.
- Refunds.
- Subscriptions.
- File Upload.
- Invitations.
- Administrative Operations.
- Role Management.

## Informações a mapear

Para cada fluxo:

- Sequência de operações.
- Endpoints envolvidos.
- Parâmetros.
- Métodos HTTP.
- Autenticação e requisitos de autorização.
- Papéis de utilizador e papéis autorizados.
- Estados da aplicação, inicial e final.
- Regras de negócio.
- Dependências entre operações.
- Alterações de estado.
- Evidências observadas.

## Formulação de hipóteses

O agente deverá procurar inconsistências entre:

- Operações permitidas e operações esperadas.
- Papéis de utilizador.
- Estados de objetos.
- Transições de estado.
- Regras de negócio.
- Validações no frontend e backend.
- Dependências entre endpoints.

Exemplo conceptual:

Uma aplicação permite criar uma encomenda, alterar o estado da encomenda e solicitar um reembolso.

O Heimdall poderá identificar o fluxo, compreender os endpoints envolvidos e formular hipóteses sobre validação de estados e autorização.

### Exemplo de fluxo

Fluxo de encomenda:

1. Criar encomenda.
2. Adicionar produtos.
3. Aplicar desconto.
4. Confirmar pagamento.
5. Consultar encomenda.
6. Solicitar reembolso.

O agente deverá compreender a sequência e identificar hipóteses de falhas nas transições de estado.

Os testes deverão utilizar encomendas e contas de teste, sem alterar transações ou dados reais.

As hipóteses deverão ser apresentadas ao utilizador com evidências e métodos de validação manual.
