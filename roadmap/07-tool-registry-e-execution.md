# Tool Registry e Execution Layer

O Heimdall deverá integrar ferramentas especializadas sem acoplar a lógica dos agentes à implementação de cada ferramenta.

## Tool Registry

Cada ferramenta deverá possuir metadados estruturados:

- Nome.
- Descrição.
- Categoria.
- Parâmetros e formato de saída.
- Permissões necessárias.
- Impacto potencial.
- Requisitos de execução.
- Timeout.
- Limites de recursos.
- Suporte a headers personalizados.
- Compatibilidade com o Policy Engine.
- Origem e versão da ferramenta.

Exemplo conceptual:

```go
type ToolDefinition struct {
    Name        string
    Description string
    Category    string
    InputSchema any
    Permissions []Permission
    Impact      ImpactLevel
    Timeout     time.Duration
}
```

A estrutura final deverá ser adaptada ao design real do projeto.

O Registry deverá permitir:

- Registar ferramentas.
- Consultar ferramentas.
- Validar argumentos.
- Verificar permissões.
- Definir timeouts.
- Classificar impacto.
- Disponibilizar apenas as ferramentas compatíveis com a decisão do Policy Engine.

## Catálogo de adapters

Nem todas as ferramentas podem ser usadas por um agente autónomo.

Cada adapter deverá declarar:

- ID e versão.
- Estágio e classe de risco.
- Tipos de alvo suportados.
- Validação de scope que aplica.
- Custo máximo.
- Como contabiliza cada request.

Apenas adapters compilados ou extensões explicitamente revistas entram no catálogo.

MCP pode ser considerado como protocolo de integração, **não como fonte de confiança**: servidores remotos não podem introduzir ferramentas implicitamente.

Subprocessos não são elegíveis para ciclos autónomos até terem accounting de request confiável, isolamento de egress e validação de argumentos. Estimativa por alvo ou parsing de stdout não contam como accounting real.

As ferramentas que não cumpram estes requisitos podem continuar disponíveis nos fluxos normais de recon, mas não no executor agentic.

`native_http_probe` é o exemplo atual de adapter de baixo impacto: uma requisição `HEAD` por alvo, sem seguir redirects e sem recolher corpos.

## Categorias

- Reconnaissance.
- DNS.
- HTTP.
- Port Scanning.
- Web Crawling.
- JavaScript Analysis.
- Content Discovery.
- API Testing.
- Browser Automation.
- Vulnerability Detection.
- Secret Detection.
- Infrastructure Analysis.
- Web Application Security.
- Code Security.
- Reporting.

## Ferramentas prioritárias

| Ferramenta | Utilização |
|---|---|
| Subfinder | Descoberta de subdomínios |
| Amass | Reconhecimento de infraestrutura |
| dnsx | Resolução DNS |
| httpx | HTTP probing |
| Naabu | Descoberta de portas |
| Katana | Crawling |
| gau | URLs históricas |
| waybackurls | URLs históricas |
| ffuf | Content discovery |
| Nuclei | Deteção baseada em templates |
| Gitleaks | Deteção de secrets |
| TruffleHog | Deteção de secrets |
| Arjun | Descoberta de parâmetros |
| ParamSpider | Parâmetros históricos |
| jsluice | Análise de JavaScript |
| LinkFinder | Extração de endpoints de JavaScript |
| Semgrep | Análise estática |
| Trivy | Análise de vulnerabilidades |
| OWASP ZAP | Testes de segurança em aplicações web |
| Burp Suite | Testes de segurança em aplicações web |

Poderá ainda ser usada análise própria em Go para extração e correlação de informação.

A integração deverá ser incremental. Não é necessário implementar todas as ferramentas na primeira versão.

## Execution Layer

O Execution Layer será responsável pela execução real das ferramentas.

Deverá:

- Executar processos externos de forma isolada.
- Validar argumentos.
- Controlar timeouts.
- Aplicar limites de CPU, memória e execução.
- Gerir processos e cancelamento.
- Capturar stdout e stderr.
- Recolher exit codes.
- Aplicar as políticas e requisitos HTTP.
- Preservar logs.
- Normalizar resultados.
- Gerir resultados e recursos.
- Registar operações para auditoria.

Deverá existir suporte para ferramentas implementadas em Go, Python e Shell. A linguagem principal do Heimdall continuará a ser Go.

O sistema deverá evitar execução arbitrária de comandos sugeridos pelo conteúdo de páginas ou por respostas não confiáveis.

## Formatos de resultados

Sempre que possível, deverá ser preferida a saída estruturada, como JSON.

Os resultados deverão ser convertidos para modelos internos normalizados.

Não deverá ser necessário que cada agente compreenda formatos proprietários diferentes.
