# Prioridades, critérios de sucesso e ciclo operacional

## Prioridades técnicas imediatas

A prioridade não deverá ser construir vários agentes especializados ou uma interface complexa.

A sequência recomendada é:

1. Consolidar o Core e os Providers existentes.
2. Implementar o Autonomous Agent Runtime.
3. Implementar o Tool Registry.
4. Implementar o Execution Layer.
5. Implementar o Policy Engine e o Program Intelligence.
6. Implementar o Request Policy Middleware.
7. Integrar o Browser Automation Engine com Playwright.
8. Implementar o Reconnaissance Engine.
9. Implementar o Target Knowledge Engine.
10. Integrar o Findings Manager.
11. Integrar o Discord.
12. Desenvolver o Business Logic Intelligence.
13. Evoluir para arquitetura Multi-Agent.
14. Iniciar a trilha Workspace/Code mode, em paralelo, depois de estabilizados o Policy Engine e o Tool Registry.

A ordem poderá ser ajustada conforme as dependências encontradas durante a implementação, mas o controlo de políticas deve existir antes da autonomia operacional sobre alvos externos.

Em paralelo com as primeiras fases, empacotar o daemon e a toolchain para VPS (Docker ou systemd), com volume de dados, healthcheck, backups e métricas. A autonomia só deve ser ativada depois de os gates operacionais passarem; detalhe em `23-operacao-e-deploy.md`.

O Discord deve ser integrado depois de existirem eventos e um modelo de Findings consistente. Isso evita construir um bot que dependa diretamente de cada ferramenta.

## Critérios de sucesso

O Heimdall deverá ser considerado funcional na sua primeira versão completa quando conseguir:

1. Criar e gerir programas e alvos.
2. Validar o scope antes das operações.
3. Executar ferramentas de reconnaissance.
4. Normalizar e correlacionar resultados.
5. Identificar ativos, tecnologias e endpoints.
6. Analisar JavaScript e extrair inteligência útil.
7. Preservar conhecimento entre execuções.
8. Consultar conhecimento anterior antes de novas investigações.
9. Identificar novas descobertas.
10. Criar Findings com evidências.
11. Notificar imediatamente o utilizador através do Discord.
12. Permitir validação manual de possíveis vulnerabilidades.
13. Registar confirmações e falsos positivos.
14. Atualizar o conhecimento com os resultados da validação.
15. Produzir relatórios técnicos.
16. Distinguir `candidate`, `reproduced` e `validated` sem promoção automática.

## Critérios globais de aceite

Além dos critérios de sucesso, qualquer versão deve cumprir:

- Zero vazamento factual entre programas/workspaces, incluindo fila, prompt, busca, artefacto e exportação.
- Zero request quando a autorização expirou, o programa pausou, o scope/source mudou, a revisão está pendente, o consentimento expirou/revogou ou o budget acabou.
- Cada request debitado no ledger antes do envio e ligado a policy revision, programa, scope, run, action e adapter.
- Todo o resultado externo tratado como dado não confiável; nenhum corpo bruto enviado ao modelo por omissão.
- Recuperação de crash não repete um efeito externo incerto sem decisão explícita.
- `candidate`, `reproduced` e `validated` são estados distintos e auditáveis; o LLM não inventa evidência.
- Nenhum shell/script arbitrário ou adapter fora do catálogo revisto.
- Avaliações offline cobrem scope positivo/negativo, exclusões, portas, redirects, limites, expiração, revogação, timeout, falha de provider e persistência de evidência.
- Um restart do daemon não duplica efeitos externos e um restore de backup foi ensaiado.
- A toolchain está fixada, o disco tem retenção e existe alerta para daemon parado.
- Nenhum segredo aparece em logs, imagens ou exportações.

Os gates detalhados e o estado atual estão em `21-estado-atual-e-gates.md`.

## Ciclo operacional pretendido

O Heimdall deverá funcionar através de um ciclo contínuo:

**Program Understanding → Scope Validation → Planning → Discovery → Browser/Tool Execution → Evidence Collection → Knowledge Update → Hypothesis Generation → Testing → Finding Creation → Human Validation → Knowledge Refinement**

Em termos práticos:

1. O utilizador adiciona um programa.
2. O Heimdall obtém e estrutura as regras.
3. O utilizador configura ou confirma as contas de teste autorizadas.
4. O sistema valida o âmbito e os requisitos obrigatórios.
5. O agente consulta a memória existente.
6. O agente planeia a investigação.
7. O agente seleciona ferramentas.
8. O Policy Engine valida as operações.
9. As ferramentas e o Browser Engine executam os testes.
10. O Evidence Collector guarda os resultados.
11. O Target Knowledge Engine atualiza a memória.
12. O agente analisa as evidências.
13. Novas hipóteses são investigadas.
14. Findings são criados quando existem evidências suficientes.
15. O Discord notifica o utilizador.
16. O utilizador valida os casos necessários.
17. O conhecimento é atualizado para investigações futuras.
