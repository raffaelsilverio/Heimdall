# Visão final

O Heimdall deverá evoluir de uma CLI com integração de modelos de IA para uma plataforma de investigação de segurança ofensiva assistida, com memória persistente, execução controlada de ferramentas e supervisão humana.

O seu diferencial não será simplesmente executar mais ferramentas ou utilizar modelos maiores.

Será a capacidade de compreender progressivamente cada alvo.

O Heimdall deverá saber:

- Que aplicações existem.
- Como estão estruturadas.
- Que tecnologias utilizam.
- Que APIs expõem.
- Que endpoints existem.
- Que parâmetros são utilizados.
- Como funciona a autenticação.
- Que papéis e permissões existem.
- Que fluxos de negócio são utilizados.
- Que comportamentos já foram investigados.
- Que hipóteses foram descartadas.
- Que vulnerabilidades foram confirmadas.
- Que evidências sustentam cada conclusão.

E, sempre que encontrar algo relevante, deverá comunicar imediatamente ao utilizador.

O utilizador não deverá precisar de acompanhar constantemente a execução no terminal. O Heimdall deverá trabalhar dentro do scope autorizado, recolher evidências, organizar descobertas e enviar relatórios pelo Discord.

O utilizador poderá então analisar cada descoberta, reproduzir manualmente o comportamento e validar possíveis vulnerabilidades. As conclusões serão preservadas e utilizadas em investigações futuras.

## Capacidades diferenciadoras

### 1. Autonomous Investigation

Um agente capaz de planear e conduzir investigações, selecionar ferramentas e decidir os próximos passos.

### 2. Persistent Target Intelligence

Uma memória técnica que acumula conhecimento sobre cada alvo, compreende a arquitetura das aplicações e reutiliza descobertas anteriores.

### 3. Browser-Assisted Security Testing

Uma capacidade de interagir com aplicações como um utilizador real, observar tráfego, compreender fluxos e investigar vulnerabilidades através de sessões de teste autorizadas.

A estas capacidades juntam-se dois princípios transversais:

### 4. Program-Aware Execution

O Heimdall deverá compreender e cumprir automaticamente as regras específicas de cada programa, incluindo scope, headers obrigatórios, User-Agent, limites de frequência, restrições de testes e requisitos de autorização.

### 5. Test-Account-First Security

O comportamento padrão deverá restringir a investigação aos dados das contas de teste criadas ou expressamente autorizadas pelo utilizador. Os testes de autorização deverão utilizar contas e recursos controlados, sem assumir que a acessibilidade técnica equivale a autorização.

## Ciclo central

```text
DISCOVERY
    │
    ▼
EVIDENCE COLLECTION
    │
    ▼
KNOWLEDGE UPDATE
    │
    ▼
FINDING CREATION
    │
    ▼
DISCORD NOTIFICATION
    │
    ▼
HUMAN VALIDATION
    │
    ▼
FINDING RESOLUTION
    │
    ▼
KNOWLEDGE REFINEMENT
    │
    ▼
BETTER FUTURE INVESTIGATIONS
```

O resultado pretendido é um sistema que não se limita a executar ferramentas: compreende o alvo, respeita as regras, investiga de forma autónoma, aprende operacionalmente com evidências e melhora progressivamente a qualidade das suas investigações.

**O Heimdall deverá funcionar como um investigador técnico persistente, que aprende com cada investigação, preserva o conhecimento dos alvos e mantém o utilizador informado e no controlo das decisões de validação.**
