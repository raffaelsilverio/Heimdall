# Visão e princípios

**Projeto:** Heimdall — Autonomous AI Security Framework
**Repositório:** `github.com/raffaelsilverio/Heimdall`
**Linguagem principal:** Go
**Browser Automation:** Python + Playwright
**Interfaces:** CLI, TUI e Discord
**Objetivo:** plataforma autónoma de investigação de segurança ofensiva, especializada em Bug Bounty e Pentesting autorizado.

---

## Visão do projeto

O Heimdall será uma plataforma de investigação de segurança ofensiva assistida por inteligência artificial, concebida para realizar investigações técnicas de forma autónoma, sistemática e contínua, cobrindo reconhecimento, análise de aplicações, descoberta de vulnerabilidades e organização de evidências.

Não deverá ser apenas um chatbot capaz de executar comandos de segurança. O objetivo é construir um sistema de investigação que compreende o contexto de cada alvo, planeia operações, utiliza ferramentas, recolhe evidências, atualiza a sua memória e decide quais são os próximos passos.

A plataforma deverá ser capaz de:

- Investigar alvos autorizados de forma sistemática.
- Descobrir e mapear superfícies de ataque.
- Compreender aplicações web, APIs, infraestrutura, serviços e fluxos de negócio.
- Identificar endpoints, parâmetros, tecnologias, autenticação, permissões e regras de negócio.
- Utilizar ferramentas especializadas de forma coordenada e autónoma.
- Correlacionar evidências de diferentes fontes e formular hipóteses de vulnerabilidade.
- Executar testes de segurança autorizados.
- Preservar conhecimento técnico sobre cada alvo ao longo do tempo.
- Reutilizar descobertas e conclusões de investigações anteriores.
- Comunicar imediatamente descobertas relevantes através do Discord.
- Permitir validação manual de possíveis vulnerabilidades.
- Aprender operacionalmente com as conclusões e evidências recolhidas.
- Produzir relatórios técnicos estruturados e fundamentados.

A característica central do Heimdall será a sua capacidade de construir conhecimento persistente sobre os alvos investigados.

Em vez de começar cada investigação do zero, deverá utilizar informações anteriormente recolhidas para orientar novas tarefas, reconhecer alterações e identificar oportunidades de investigação.

## Modelo de operação

O Heimdall deverá ser **autónomo na descoberta, limitado na ação e humano na validação**:

- Descobre, correlaciona e planeia sem intervenção constante.
- Executa apenas ações permitidas pelo programa, com consentimento, budgets e quotas.
- Não confirma vulnerabilidades nem submete relatórios sem validação humana.

## Princípios

O desenvolvimento deverá seguir os seguintes princípios:

1. **AI-assisted:** a inteligência artificial coordena, interpreta e planeia as investigações; as ferramentas executam operações técnicas concretas.
2. **Autonomia controlada:** os agentes podem planear e executar investigações sem instruções humanas para cada operação, mas nunca ultrapassam o âmbito autorizado, as regras do programa ou as permissões do utilizador.
3. **Tool-driven e tool-agnostic:** o sistema não depende de uma ferramenta específica; ferramentas, agentes, modelos e interfaces podem ser substituídos.
4. **Model-agnostic:** diferentes fornecedores e modelos de IA podem ser utilizados sem alterar o Agent Runtime.
5. **Knowledge-centric:** o conhecimento acumulado sobre os alvos é um componente central e sobrevive entre sessões.
6. **Human-in-the-Loop:** o utilizador acompanha, aprova e valida as operações e conclusões que o exijam.
7. **Event-driven:** descobertas e alterações geram eventos que desencadeiam notificações, tarefas e atualizações de conhecimento.
8. **Evidence-based / Evidence First:** nenhuma vulnerabilidade é considerada confirmada sem evidências suficientes e verificáveis. Uma hipótese produzida por um modelo não é uma vulnerabilidade demonstrada.
9. **Scope-aware / Policy First:** todas as operações respeitam os limites de autorização dos programas; as regras específicas de cada programa prevalecem sobre comportamentos genéricos do sistema.
10. **Security by Design:** autorização, âmbito e regras de execução são aplicados centralmente pelo sistema, não apenas pelo prompt do agente.
11. **Incremental:** as capacidades são implementadas progressivamente, sem criar antecipadamente uma estrutura excessivamente complexa.
12. **Modular:** cada capacidade possui responsabilidades bem definidas.

## Aprendizagem operacional contínua

O Heimdall deverá melhorar a qualidade das suas investigações à medida que acumula conhecimento.

Ao investigar repetidamente uma aplicação, deverá aprender e preservar:

- Estrutura da aplicação.
- Domínios e subdomínios.
- Endpoints e parâmetros.
- Tecnologias utilizadas.
- Sistemas de autenticação.
- Tipos de utilizadores e respetivas permissões.
- Fluxos de negócio.
- Dependências entre serviços.
- Comportamentos observados.
- Vulnerabilidades anteriormente identificadas.
- Testes realizados e respetivos resultados.
- Hipóteses confirmadas ou rejeitadas.
- Alterações na superfície de ataque.

Este conhecimento deverá ser utilizado nas investigações futuras.

A melhoria será operacional: melhores hipóteses, planeamento, seleção de ferramentas, correlação e reutilização de evidências. Não pressupõe treino automático dos pesos dos modelos de IA.
