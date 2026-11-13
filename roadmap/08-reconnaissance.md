# Reconnaissance Engine

O Reconnaissance Engine será um dos componentes mais importantes do Heimdall.

A reconnaissance não deverá ser tratada apenas como uma fase inicial. Deverá ser um processo contínuo de descoberta, atualização e compreensão da superfície de ataque.

O princípio é simples:

**O objetivo não é apenas encontrar subdomínios. É compreender a aplicação e a sua superfície de ataque.**

O reconhecimento deverá seguir uma abordagem progressiva:

**Passive Recon → Active Recon → Discovery → Correlation → Knowledge Update**

## Pipeline de reconhecimento

```text
Scope Validation
      │
      ▼
Passive Asset Discovery
      │
      ▼
Subdomain Enumeration
      │
      ▼
DNS Resolution
      │
      ▼
HTTP Probing
      │
      ▼
Technology Fingerprinting
      │
      ▼
Historical URL Discovery
      │
      ▼
Web Crawling
      │
      ▼
JavaScript Intelligence
      │
      ▼
Endpoint Discovery
      │
      ▼
Parameter Discovery
      │
      ▼
Content Discovery
      │
      ▼
Public Exposure Intelligence
      │
      ▼
Template-based Detection
      │
      ▼
Correlation
      │
      ▼
Target Knowledge Update
```

Cada etapa deverá produzir resultados estruturados e reutilizáveis.

## 1. Scope Validation

- Validar domínios.
- Identificar ativos autorizados.
- Identificar exclusões.
- Validar DNS e redirecionamentos.
- Aplicar regras e requisitos do programa.

## 2. Passive Asset Discovery

Recolha de informações sem interação ativa significativa com a infraestrutura do alvo.

Fontes possíveis:

- Certificate Transparency.
- crt.sh.
- Wayback Machine.
- Common Crawl.
- DNS aggregators.
- VirusTotal.
- AlienVault OTX.
- SecurityTrails.
- Repositórios públicos.
- Motores de pesquisa.

Ferramentas:

- Subfinder.
- Amass em modo passivo.
- gau.
- waybackurls.

Os resultados de diferentes fontes deverão ser combinados e deduplicados.

O Heimdall deverá preservar a origem de cada descoberta, permitindo identificar quais as fontes que produzem mais resultados relevantes.

## 3. Subdomain Enumeration

Descoberta de subdomínios através de múltiplas fontes.

O sistema deverá:

1. Recolher subdomínios.
2. Normalizar os resultados.
3. Remover duplicados.
4. Associar a origem.
5. Classificar por confiança.
6. Resolver DNS.
7. Identificar alterações.
8. Atualizar o inventário de ativos.

Ferramentas:

- Subfinder.
- Amass.
- crt.sh.
- dnsx.

## 4. DNS Resolution

Identificação dos endereços associados aos domínios.

Informações a preservar:

- A.
- AAAA.
- CNAME.
- NS.
- MX.
- TXT.
- IP associado.
- Histórico de resolução.
- Relações entre subdomínios e infraestrutura.

Ferramenta principal: dnsx.

O sistema deverá conseguir identificar alterações de DNS e relações relevantes entre ativos.

## 5. HTTP Probing

Identificação dos serviços HTTP e HTTPS.

Ferramenta principal: httpx.

Informações relevantes:

- URL.
- Status code.
- Page title.
- Technologies.
- Web server.
- IP.
- Redirects.
- Content type.
- Response headers.
- Content length.
- Certificado e informação TLS.
- Metadados relevantes.

Respostas 401, 403 e outras respostas de acesso restrito não deverão ser descartadas. Podem representar aplicações, painéis administrativos ou endpoints relevantes.

Todas as requisições devem respeitar os requisitos HTTP definidos pelo programa.

## 6. Technology Fingerprinting

Identificação das tecnologias utilizadas.

Exemplos:

- Frameworks.
- CMS.
- Web servers.
- Reverse proxies.
- CDNs.
- Linguagens.
- Bibliotecas frontend e backend.
- Sistemas de autenticação.
- Infraestrutura cloud.
- Serviços externos.

O conhecimento deverá associar tecnologias a aplicações e serviços concretos.

## 7. Historical URL Discovery

A recolha de URLs históricas pode revelar funcionalidades que já não estão visíveis na interface atual.

Fontes e ferramentas:

- Wayback Machine.
- gau.
- waybackurls.
- Common Crawl.

O Heimdall deverá:

- Recolher URLs.
- Normalizar caminhos.
- Identificar parâmetros.
- Agrupar endpoints semelhantes.
- Associar URLs às aplicações.
- Comparar URLs históricas com endpoints atuais.
- Identificar funcionalidades potencialmente descontinuadas.

## 8. Web Crawling

Crawling de aplicações web para descobrir caminhos, recursos e relações.

Ferramenta principal: Katana.

Deverá suportar:

- Controlo de profundidade.
- Respeito pelos limites de scope.
- Limites de velocidade.
- Identificação de recursos JavaScript.
- Extração de links.
- Recolha de formulários.
- Descoberta de endpoints e parâmetros.
- Associação de páginas e recursos.
- Estrutura de navegação.

As etapas seguintes do pipeline — JavaScript Intelligence, Endpoint Discovery, Parameter Discovery, Content Discovery, Public Exposure Intelligence, Template-based Detection e correlação — estão descritas em `09-javascript-e-descoberta.md`.
