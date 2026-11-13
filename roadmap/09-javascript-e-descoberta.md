# JavaScript Intelligence e descoberta de ativos

Esta secção cobre as etapas do Reconnaissance Engine que transformam ativos descobertos em conhecimento utilizável: análise de JavaScript, endpoints, parâmetros, conteúdo, exposições públicas, deteção por templates e correlação.

## 9. JavaScript Intelligence

Este será um dos componentes prioritários do Reconnaissance Engine.

JavaScript pode revelar uma parte significativa da arquitetura interna de uma aplicação.

O Heimdall deverá tratar os ficheiros JavaScript como fontes de inteligência técnica.

### Processo

1. Identificar ficheiros JavaScript.
2. Recolher os ficheiros autorizados.
3. Guardar URL, hash e versão.
4. Extrair caminhos e endpoints.
5. Extrair parâmetros.
6. Identificar métodos HTTP quando possível.
7. Identificar hosts e referências a APIs.
8. Identificar mecanismos de autenticação.
9. Analisar padrões de construção de rotas.
10. Correlacionar resultados com o inventário existente.

Ferramentas possíveis:

- Katana.
- LinkFinder.
- jsluice.
- Análise própria em Go.

### Análise contextual

A extração automática de strings não é suficiente.

O agente deverá conseguir analisar o contexto do código para compreender:

- Como são construídas as rotas.
- Que parâmetros são utilizados.
- Que funções chamam determinadas APIs.
- Que mecanismos de autenticação são utilizados.
- Que operações estão associadas a cada endpoint.
- Que dependências existem entre funcionalidades.

O sistema deverá distinguir:

- Endpoint inferido.
- Endpoint observado em código.
- Endpoint observado em tráfego.
- Endpoint acessível.
- Endpoint validado.

Não deverá classificar um caminho extraído de JavaScript como funcionalidade confirmada sem evidência adicional. A presença de uma rota no JavaScript não comprova que esteja ativa ou acessível.

### Identificação de exposições

A análise deverá procurar possíveis exposições de:

- API keys.
- Tokens.
- Credenciais.
- Configurações internas.
- URLs de serviços.
- Referências a ambientes de desenvolvimento.

Deverá distinguir chaves públicas legítimas de credenciais que representam efetivamente um risco.

## 10. Endpoint Discovery

Todos os endpoints descobertos deverão ser registados no conhecimento do alvo.

Informações:

- URL.
- Método HTTP.
- Parâmetros.
- Aplicação.
- Domínio.
- API associada.
- Origem da descoberta.
- Autenticação necessária.
- Papel necessário.
- Estado de observação e validação.
- Evidências.
- Última observação.

O Heimdall deverá conseguir identificar endpoints duplicados, versões antigas e alterações de comportamento.

## 11. Parameter Discovery

Descoberta de parâmetros através de fontes históricas, crawling, análise de aplicações e testes ativos autorizados.

Ferramentas:

- ParamSpider.
- Arjun.
- ffuf.

Tipos de parâmetros a descobrir:

- GET.
- POST.
- JSON.
- Formulários.
- Parâmetros históricos.
- Parâmetros identificados em JavaScript.

O sistema deverá distinguir parâmetros:

- Encontrados em URLs históricas.
- Extraídos de JavaScript.
- Observados em formulários.
- Observados em tráfego.
- Confirmados através de interação autorizada.

A descoberta deverá ser progressiva, começando por fontes passivas e avançando para testes ativos autorizados.

## 12. Content Discovery

Descoberta de conteúdos e caminhos através de ferramentas como ffuf.

Deverá existir controlo de:

- Scope.
- Concorrência.
- Rate limits.
- Timeouts.
- Extensões.
- Wordlists.
- Volume de pedidos.

Objetivos:

- Diretórios.
- Ficheiros.
- Recursos.
- Endpoints.
- Painéis.
- Funcionalidades não documentadas.

Os resultados deverão ser correlacionados com os endpoints já conhecidos e respeitar as restrições específicas do programa.

## 13. Public Exposure Intelligence

Identificação de possíveis exposições em fontes públicas.

Exemplos:

- Repositórios públicos.
- Ficheiros de configuração.
- Credenciais expostas.
- Secrets.
- Endpoints internos referenciados publicamente.
- Documentação técnica.
- Ficheiros esquecidos.

Ferramentas:

- Gitleaks.
- TruffleHog.

Uma string identificada como potencial segredo não deverá ser considerada uma credencial válida sem validação apropriada e autorização.

É necessário distinguir chaves públicas utilizadas no frontend de credenciais e secrets efetivamente sensíveis.

## 14. Template-based Detection

Integração com Nuclei para deteção baseada em templates.

O resultado deverá ser tratado como uma indicação para investigação, não como prova automática de vulnerabilidade.

O Heimdall deverá:

1. Registar o template utilizado.
2. Preservar o resultado.
3. Identificar o ativo afetado.
4. Avaliar a confiança.
5. Correlacionar com outras evidências.
6. Criar uma hipótese quando apropriado.
7. Enviar a descoberta para o Findings Manager.

A confirmação deverá depender de evidências suficientes e validação.

## 15. Correlation and Knowledge Update

Correlacionar:

- Subdomínios.
- DNS.
- Serviços.
- Aplicações.
- Endpoints.
- Parâmetros.
- JavaScript.
- Tecnologias.
- Resultados de ferramentas.
- Evidências anteriores.

O resultado deverá atualizar continuamente o Target Knowledge Engine, preservando origem, confiança e histórico de cada informação.
