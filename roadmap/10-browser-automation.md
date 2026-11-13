# Browser Automation Engine

O Browser Automation Engine será uma capacidade central do Heimdall, disponível aos agentes autónomos através do Tool Registry.

O agente deverá poder decidir autonomamente quando precisa de utilizar um navegador para investigar uma aplicação.

A implementação do browser deverá estar separada do Agent Runtime.

**O agente decide e coordena. O Browser Engine executa e observa.**

## Tecnologia

Decisão inicial:

- Core: Go.
- Browser Worker: Python.
- Browser Automation: Playwright.
- Comunicação: JSON sobre HTTP local.
- Browser inicial: Chromium.
- Expansão futura: Firefox e WebKit.

A escolha de Python para o worker permite utilizar a implementação oficial de Playwright sem transformar o backend principal do Heimdall numa aplicação Python.

O Core continuará em Go.

## Componentes

### Browser Manager

Responsável por:

- Iniciar navegadores.
- Encerrar navegadores.
- Gerir instâncias.
- Controlar recursos.
- Gerir configurações.

### Session Manager

Responsável por:

- Cookies.
- Sessões.
- Autenticação.
- Tokens.
- Contextos isolados.
- Associação de sessões às contas de teste.

Cada sessão deverá estar associada a uma identidade autorizada.

### Navigation Engine

Responsável por:

- Navegação.
- Cliques.
- Preenchimento de formulários.
- Interação com elementos.
- Submissão de operações.
- Navegação entre páginas.

### Network Observer

Responsável por observar:

- Requests.
- Responses.
- Headers.
- Cookies.
- Métodos HTTP.
- URLs.
- Payloads.
- Status codes.
- Redirecionamentos.

Deverá aplicar os requisitos obrigatórios do programa às requisições realizadas pelo browser, incluindo os headers de identificação exigidos.

Não deverá encaminhar cookies, tokens ou headers sensíveis para origens externas não autorizadas.

### DOM Inspector

Responsável por:

- Inspecionar a estrutura HTML.
- Identificar formulários.
- Identificar campos.
- Identificar elementos interativos.
- Observar alterações na interface.

### JavaScript Inspector

Responsável por:

- Capturar erros JavaScript.
- Observar eventos.
- Identificar comportamentos client-side.
- Analisar Local Storage.
- Analisar Session Storage.
- Identificar informação exposta no frontend.

### Evidence Collector

Responsável por guardar:

- Screenshots.
- Requests.
- Responses.
- Headers.
- DOM relevante.
- Logs.
- JavaScript errors.
- Traces.
- Resultados de testes.

### Test Executor

Responsável por executar procedimentos de teste solicitados pelos agentes.

Deverá validar permissões, políticas e requisitos antes da execução.

## Browser Reconnaissance

O browser não deverá servir apenas para testar vulnerabilidades.

Também deverá ajudar a compreender o funcionamento real das aplicações.

O agente poderá:

- Navegar pela aplicação.
- Descobrir funcionalidades.
- Identificar fluxos de utilizador.
- Observar endpoints utilizados pelo frontend.
- Identificar chamadas API.
- Observar parâmetros.
- Identificar mecanismos de autenticação.
- Descobrir alterações de estado.
- Identificar dependências entre operações.

Esta informação deverá alimentar o Target Knowledge Engine.

## Browser-Assisted Security Testing

O browser deverá permitir investigar:

- Authentication.
- Authorization.
- IDOR/BOLA.
- XSS.
- CSRF.
- Session Management.
- Client-Side Security.
- API Security.
- File Upload.
- Business Logic Vulnerabilities.

O agente deverá poder construir testes utilizando sessões de contas de teste autorizadas.

### Exemplo: investigação de IDOR

1. Reconhecimento identifica um endpoint que consulta recursos de utilizadores.
2. O Heimdall identifica duas contas de teste autorizadas.
3. O agente inicia uma sessão da Conta A.
4. Observa os pedidos HTTP.
5. Identifica os identificadores de recursos pertencentes à Conta A.
6. Inicia uma sessão da Conta B.
7. Compara o comportamento de acesso aos recursos de teste.
8. Recolhe requests, responses e screenshots.
9. Analisa as diferenças.
10. Cria uma hipótese de vulnerabilidade.
11. Atualiza as evidências.
12. Notifica o utilizador.

A diferença entre duas respostas não é automaticamente uma vulnerabilidade. O agente deverá avaliar o contexto, os controlos de autorização e as evidências disponíveis.

O acesso a dados de utilizadores reais não faz parte do comportamento padrão.

## Browser Handoff

O Browser Handoff permitirá que o utilizador assuma o controlo de uma investigação.

Fluxo:

1. O agente inicia uma investigação.
2. Recolhe evidências iniciais.
3. Guarda o estado da sessão de teste.
4. Identifica uma hipótese que necessita de validação.
5. Envia uma notificação ao Discord.
6. O utilizador recebe a oportunidade de inspecionar a sessão.
7. O utilizador reproduz ou analisa o comportamento.
8. Regista o resultado.
9. O Heimdall atualiza o finding e a memória do alvo.

As credenciais e os cookies nunca deverão ser enviados diretamente através do Discord.
