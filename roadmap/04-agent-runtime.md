# Autonomous Agent Runtime

O Autonomous Agent Runtime será o núcleo de inteligência do Heimdall.

É responsável por executar agentes capazes de planear, investigar, utilizar ferramentas, analisar resultados e decidir os próximos passos.

A implementação inicial deverá utilizar **um agente generalista**, com acesso controlado a ferramentas e memória persistente. A especialização deverá acontecer progressivamente.

## Funcionamento do agente

O ciclo principal será:

1. Receber um objetivo.
2. Consultar o contexto do projeto e do alvo.
3. Consultar as regras do programa.
4. Consultar o conhecimento acumulado.
5. Definir uma estratégia de investigação.
6. Selecionar ferramentas.
7. Solicitar execução através do Tool Registry.
8. Analisar os resultados.
9. Atualizar o conhecimento.
10. Formular novas hipóteses.
11. Decidir os próximos passos.
12. Criar findings quando existirem evidências suficientes.
13. Notificar o utilizador quando necessário.

O agente deverá poder repetir este ciclo autonomamente até concluir o objetivo, atingir um limite operacional ou necessitar de intervenção humana.

## Planeamento

O Planner é uma capacidade interna do Agent Runtime.

Deverá:

- Transformar objetivos em planos estruturados.
- Dividir objetivos em tarefas.
- Identificar dependências entre tarefas.
- Considerar resultados e conhecimento anteriores.
- Evitar tarefas redundantes.
- Replanear após cada resultado relevante.
- Produzir workflows reutilizáveis.
- Integrar eventos e findings no plano.

Antes de iniciar uma investigação, o agente deverá consultar a memória do alvo e identificar lacunas de conhecimento, em vez de repetir toda a reconnaissance.

## Capacidades do runtime

Deverá suportar:

- Context management.
- Tool calling e Function Calling.
- Planning.
- Task execution.
- Iteration.
- Result evaluation.
- Error handling.
- Context compression.
- Execution limits.
- Timeouts.
- Cancelamento.
- Registo e histórico de execuções.

## Autonomia e utilização de ferramentas

O agente deverá ter acesso a diferentes categorias de ferramentas:

- Ferramentas de terminal.
- Ferramentas de reconhecimento.
- Ferramentas HTTP.
- Ferramentas de análise de aplicações web.
- Browser Automation.
- Ferramentas de análise de JavaScript.
- Ferramentas de análise de APIs.
- Ferramentas de análise de infraestrutura.
- Ferramentas de gestão de evidências.

A utilização será realizada através de Function Calling e de uma interface uniforme de ferramentas.

O agente escolhe a ferramenta e os argumentos. O sistema valida permissões, políticas e âmbito, e só depois executa a operação.

A autonomia não significa autoridade ilimitada. O agente não pode ultrapassar o âmbito autorizado, as regras do programa ou as permissões do utilizador.

## Especialização futura dos agentes

A arquitetura deverá permitir agentes especializados:

| Agente | Responsabilidade |
|---|---|
| Recon Agent | Reconhecimento e descoberta de ativos |
| JavaScript Agent | Análise de JavaScript e descoberta de endpoints |
| Web Security Agent | Testes de segurança em aplicações web |
| API Security Agent | Investigação de APIs |
| Infrastructure Agent | Serviços, servidores e infraestrutura |
| Business Logic Agent | Fluxos e regras de negócio |
| Authentication Agent | Autenticação, sessões e autorização |
| Vulnerability Agent | Investigação e validação de vulnerabilidades |
| Reporting Agent | Relatórios técnicos |

A especialização deverá acontecer quando a complexidade justificar essa divisão, mantendo coordenação centralizada e as mesmas políticas de execução.
