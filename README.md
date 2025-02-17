# VulnBuilderAI: Ferramenta Multiplataforma para Construção de Datasets de Vulnerabilidades com Categorização por IA

[![Licença](https://img.shields.io/badge/License-GNU%20GPL-blue)](https://opensource.org/licenses/GNU)

**Resumo do Artigo:**

_Este projeto apresenta o VulnBuilderAI, uma ferramenta para construir datasets de vulnerabilidades de software. A ferramenta coleta dados de múltiplas fontes, normaliza, extrai informações relevantes usando PLN (incluindo LLMs) e categoriza as vulnerabilidades. O objetivo é gerar datasets de alta qualidade para pesquisa e prática em segurança de software._

---

## Estrutura do README.md

Este README.md está organizado nas seguintes seções:

1.  **Título e Resumo:** Título do projeto e um resumo conciso (cópia do resumo do artigo).
2.  **Funcionalidades:** Lista as principais funcionalidades da ferramenta.
3.  **Pré-requisitos:** Lista os requisitos de software (Python, APIs).
4.  **Instalação:** Instruções passo a passo para instalar a ferramenta.
5.  **Configuração:** Instruções para configurar as chaves de API.
6.  **Uso:** Explicação dos argumentos de linha de comando e exemplos de uso.
7.  **Docker (Opcional):** Instruções para construir e executar a ferramenta usando Docker.
8.  **Estrutura do Código:** Breve visão geral da organização do código-fonte.
9.  **Licença:** Informações sobre a licença do projeto.
10. **Contribuindo:** (Opcional) Instruções para quem quiser contribuir.
11. **Contato:** (Opcional) Informações de contato dos autores.
12. **Selos Considerados** (Adicionado,conforme as instruções).

---

## Selos Considerados

Este artefato está submetido para avaliação dos seguintes selos:

- Disponíveis
- Funcionais
- Sustentáveis
- Experimentos Reprodutíveis

---

## Funcionalidades

- **Coleta de Dados:** Busca dados de vulnerabilidades em múltiplas fontes:
  - NVD (National Vulnerability Database)
  - Vulners
  - GitHub (através de uma API, _implementação futura_)
- **Processamento de Dados:**
  - Normalização e limpeza dos dados.
  - Remoção de duplicatas.
  - Truncamento de descrições longas.
  - Filtragem de vulnerabilidades por critérios (e.g., fornecedor).
- **Extração de Informações:** Extrai informações relevantes das descrições das vulnerabilidades, como:
  - ID da vulnerabilidade (CVE, etc.)
  - Título
  - Descrição
  - Fornecedor
  - Data de publicação
  - Score CVSS (se disponível)
  - Severidade (se disponível)
  - Fonte da informação
- **Categorização com IA:**
  - Utiliza modelos de linguagem (LLMs) para categorizar as vulnerabilidades:
    - Google Gemini
    - OpenAI ChatGPT
    - Meta Llama 3
  - Extrai as seguintes informações usando os LLMs:
    - Categoria CWE (Common Weakness Enumeration)
    - Explicação da CWE
    - Fornecedor
    - Causa da vulnerabilidade
    - Impacto da vulnerabilidade
  - Sistema de votação ponderada para combinar os resultados dos diferentes LLMs.
- **Exportação de Dados:**
  - Exporta os dados processados e categorizados para arquivos CSV ou JSON.
- **Extensibilidade:**
  - Arquitetura modular que facilita a adição de novas fontes de dados e novos modelos de IA.
- **Linha de Comando:**
  - Interface de linha de comando para facilitar o uso da ferramenta.

## Pré-requisitos

- Python 3.8 ou superior.
- Chaves de API para os seguintes serviços (opcional, dependendo dos módulos e LLMs que você for usar):
  - **Vulners:** Obtenha uma chave em [https://vulners.com/](https://vulners.com/)
  - **Google Gemini:** Obtenha uma chave em [https://ai.google.dev/](https://ai.google.dev/)
  - **OpenAI ChatGPT:** Obtenha uma chave em [https://platform.openai.com/](https://platform.openai.com/)
  - **Llama (Meta):** Obtenha uma chave em [https://llama-api.com/](https://llama-api.com/)

## Instalação

1.  **Clone o repositório:**

    ```bash
    git clone https://github.com/douglasfideles/VulnBuilderAI.git
    cd VulnBuilderAI
    ```

2.  **Crie um ambiente virtual (recomendado):**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    .venv\Scripts\activate  # Windows
    ```

3.  **Instale as dependências:**

    ```bash
    pip install -r requirements.txt
    ```

    Caso tenha problemas, instale individualmente:

    ```bash
      pip install google-generativeai
      pip install openai
      pip install requests
    ```

## Configuração

Você pode configurar o VulnBuilderAI usando _variáveis de ambiente_ ou _argumentos de linha de comando_. A ordem de prioridade é: argumentos de linha de comando > variáveis de ambiente.

1.  **Defina as chaves de API (opcional):**

    - **Variáveis de ambiente (recomendado):**

      ```bash
      export VULNERS_API_KEY=sua_chave_vulners
      export GEMINI_API_KEY=sua_chave_gemini
      export CHATGPT_API_KEY=sua_chave_chatgpt
      export LLAMA_API_KEY=sua_chave_llama
      ```

      Substitua `sua_chave_...` pelas suas chaves de API reais. _Não_ coloque as chaves diretamente no código-fonte!

    - **Argumentos de linha de comando:** Você também pode passar as chaves diretamente ao executar o script (veja a seção "Uso").

2.  **Arquivo de configuração (opcional):**
    _Não implementado no código fornecido._ Se você quisesse adicionar um arquivo de configuração (e.g., `config.ini` ou `config.yaml`), precisaria modificar o código (`main.py`) para ler as configurações desse arquivo.

## Uso

### Argumentos de Linha de Comando

```bash
python src/main.py --source <ai_provider> --data-source <data_source> --vulners-key <vulners_key> --gemini-key <gemini_key> --chatgpt-key <chatgpt_key> --llama-key <llama_key>  --export-format <format> --output-file <filename>  --search-params <params> --search-file <file_path>
```

- `--source`: **Obrigatório.** Seleciona o provedor de IA para categorização. Opções:
  - `gemini`: Usa o Google Gemini.
  - `chatgpt`: Usa o OpenAI ChatGPT.
  - `llama`: Usa o Meta Llama.
  - `combined`: Usa _todos_ os modelos acima, com um sistema de votação ponderada.
  - `none`: _Não_ usa IA para categorização (útil para coletar e normalizar dados sem categorizar).
- `--data-source`: **Obrigatório.** Seleciona a fonte de dados de vulnerabilidades. Opções:
  - `nvd`: Usa o National Vulnerability Database (NVD).
  - `vulners`: Usa a API do Vulners.
  - `both`: Usa _ambas_ as fontes (NVD e Vulners).
- `--gemini-key`: Chave de API para o Google Gemini (se `--source` for `gemini` ou `combined`).
- `--chatgpt-key`: Chave de API para o OpenAI ChatGPT (se `--source` for `chatgpt` ou `combined`).
- `--llama-key`: Chave de API para o Llama (se `--source` for `llama` ou `combined`).
- `--default-key`: Chave de API Default para LLM
- `--default-url`: Base URL para Default LLM
- `--default-model`: Modelo para Default LLM
- `--vulners-key`: Chave de API para o Vulners (se `--data-source` for `vulners` ou `both`).
- `--export-format`: Formato de exportação dos dados. Opções:
  - `csv`: Arquivo CSV (Comma-Separated Values).
  - `json`: Arquivo JSON.
  - O padrão é `csv`.
- `--output-file`: Nome do arquivo de saída (e caminho, se necessário). O padrão é `dataset/dds_vulnerabilities_AI.csv`.
- `--search-params`: Parâmetros de busca para vulnerabilidades (palavras-chave separadas por espaço). _Exemplo:_ `"OpenDDS" "RTI Connext DDS"`
- `--search-file`: Caminho para um arquivo _de texto_ contendo os parâmetros de busca (uma palavra-chave ou frase por linha). _Exemplo:_ `search_params.txt`

### Exemplos de Comando

1.  **Usando todas as IAs, ambas as fontes e múltiplos termos de busca:**

    ```bash
    python src/main.py --source combined --data-source both --search-params "OpenDDS" "RTI Connext DDS" --gemini-key <SUA_CHAVE_GEMINI> --chatgpt-key <SUA_CHAVE_CHATGPT> --llama-key <SUA_CHAVE_LLAMA>  --vulners-key <SUA_CHAVE_VULNERS> --export-format csv --output-file vulnerabilidades.csv
    ```

    - `--source combined`: Usa Gemini, ChatGPT e Llama, com votação.
    - `--data-source both`: Usa NVD e Vulners.
    - `--search-params`: Busca por vulnerabilidades relacionadas a "OpenDDS" _e_ "RTI Connext DDS".
    - As chaves de API são fornecidas.
    - O resultado é salvo em `vulnerabilidades.csv`.

2.  **Sem IA, usando apenas o NVD:**

    ```bash
    python src/main.py --source none --data-source nvd --search-params "OpenDDS" --export-format csv --output-file vulnerabilidades_nvd.csv
    ```

    - `--source none`: _Não_ usa IA para categorização. Os campos de categoria (CWE, etc.) ficarão como "UNKNOWN".
    - `--data-source nvd`: Usa _apenas_ o NVD.
    - Não precisa de chaves de API de LLMs.

3.  **Usando Gemini, Vulners e um arquivo com termos de busca:**

    Crie um arquivo `search_terms.txt` com o seguinte conteúdo (um termo por linha):

    ```
    OpenDDS
    RTI Connext DDS
    Eclipse Cyclone DDS
    ```

    Execute:

    ```bash
    python src/main.py --source gemini --data-source vulners --search-file search_terms.txt --vulners-key <SUA_CHAVE_VULNERS> --gemini-key <SUA_CHAVE_GEMINI> --output-file vulnerabilidades_gemini.csv
    ```

    - `--source gemini`
    - `--search-file`: Usa o arquivo `search_terms.txt`.
4.  **Usando Default, Vulners (e. g.) e um arquivo com termos de busca:**

    Crie um arquivo `search_terms.txt` com o seguinte conteúdo (um termo por linha):

    ```
    OpenDDS
    RTI Connext DDS
    Eclipse Cyclone DDS
    ```

    Execute:

    ```bash
    python src/main.py --source default --data-source vulners --search-file search_terms.txt --vulners-key <SUA_CHAVE_VULNERS> --default-key <SUA_CHAVE_DEFAULT> --default-model <MODELO_DEFAULT_LLM> --default-url <BASE_URL_DEFAULT> --output-file vulnerabilidades_default.csv
    ```

    - `--source default`
    - `--search-file`: Usa o arquivo `search_terms.txt`.

## Docker

Você também pode executar o script usando Docker.

### Dockerfile

```dockerfile
# Use uma imagem oficial do Python como imagem base
FROM python:3.9-slim

# Defina o diretório de trabalho no contêiner
WORKDIR /app

# Copie o conteúdo do diretório atual para o contêiner em /app
COPY . /app

# Instale os pacotes necessários especificados em requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Defina a variável de ambiente
ENV NAME DDSBuilder

# Execute main.py quando o contêiner for iniciado
CMD ["python", "src/main.py"]
```

### Construir e Executar o Contêiner Docker

1.  **Construir a imagem:**

    ```bash
    docker build -t vbuilder .
    ```

2.  **Executar o container usando IA para categorização:**

    ```bash
    docker run vbuilder python src/main.py --source combined --data-source both --vulners-key <SUA_CHAVE_VULNERS> --gemini-key <SUA_CHAVE_GEMINI> --chatgpt-key <SUA_CHAVE_CHATGPT>  --llama-key <SUA_CHAVE_LLAMA>  --export-format csv --output-file vulnerabilidades.csv --search-params "OpenDDS" "RTI Connext DDS"
    ```

3.  **Executar o container sem usar IA para categorização:**

    ```bash
    docker run --source none --data-source nvd --export-format csv --output-file vulnerabilidades.csv --search-params "OpenDDS"
    ```

## Estrutura do Código

O código-fonte está organizado da seguinte forma:

- `categorization/`: Contém os módulos relacionados à categorização de vulnerabilidades com IA.
  - `categorizer.py`: Implementa a classe `Categorizer`, responsável por interagir com as APIs dos LLMs e combinar os resultados.
  - `__init__.py`
  - `voting.py`: Implementa um sistema de votação.
- `data_sources/`: Contém os módulos para extrair dados de diferentes fontes.
  - `nvd_extractor.py`: Funções para acessar a API do NVD.
  - `vulners_extractor.py`: Funções para acessar a API do Vulners.
  - `__init__.py`
- `output/`: Contém os módulos para exportar os dados processados.
  - `csv_exporter.py`: Funções para exportar dados para CSV.
  - `__init__.py`
  - `json_exporter.py`: Funções para exportar dados para JSON.
- `processing/`: Contém módulos para processamento e normalização dos dados.
  - `filter.py`: Funções para filtrar as vulnerabilidades.
  - `normalizer.py`: Funções para normalizar os dados de diferentes fontes.
  - `__init__.py`
- `src/`: Contém o script principal.
  - `main.py`: Ponto de entrada principal do programa.
- `requirements.txt`: Lista as dependências do projeto.
- `README.md`: Este arquivo.
- search-params-\*.txt: Arquivos contendo termos para pesquisa.

## Licença

Este projeto está licenciado sob a Licença GNU - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
