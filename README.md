# Coletor de Vulnerabilidades DDS com IA para Categorização

Este script Python coleta informações de vulnerabilidades relacionadas ao DDS (Data Distribution Service) de várias fontes (NVD, Vulners, GitHub) e usa IA (Google Gemini, ChatGPT, Llama) para categorizar cada vulnerabilidade em uma categoria CWE, identificar o fornecedor e extrair a causa e o impacto da vulnerabilidade.

## Funcionalidades

- Coleta dados de vulnerabilidades do NVD, Vulners e GitHub.
- Usa IA para categorizar vulnerabilidades e extrair informações relevantes.
- Suporta múltiplos provedores de IA: Google Gemini, ChatGPT e Llama.
- Lida com vulnerabilidades duplicadas e normaliza os dados.
- Exporta dados para formatos CSV e JSON.
- Possibilidade de usar a ferramenta sem IA.

## Pré-requisitos

- Python 3.8 ou superior: Certifique-se de ter o Python instalado. Você pode baixá-lo [aqui](https://www.python.org/downloads/).
- Chaves de API para os seguintes serviços:
  - Vulners: Obtenha em [Vulners](https://vulners.com/)
  - Google Gemini: Obtenha em [Google Gemini](https://developers.google.com/generative-ai)
  - ChatGPT: Obtenha em [OpenAI](https://openai.com/)
  - Llama: Obtenha em [Llama](https://llama-api.com/)

## Instalação

1. Clone o repositório:

   ```bash
   git clone https://github.com/seuusuario/DDSBuilder.git
   cd DDSBuilder
   ```

2. Crie e ative um ambiente virtual (recomendado):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate  # Windows
   ```

3. Instale os pacotes necessários:

   ```bash
   pip install -r requirements.txt
   ```

   Certifique-se de que o `google-generativeai` esteja instalado. Se necessário, instale-o separadamente:

   ```bash
   pip install google-g
   ```

## Configuração

Você pode configurar o DDS-Builder usando variáveis de ambiente, um arquivo de configuração ou argumentos de linha de comando. A ordem de prioridade é: argumentos de linha de comando > variáveis de ambiente > arquivo de configuração.

1. Defina as chaves de API como variáveis de ambiente:

   ```bash
   export VULNERS_API_KEY=sua_chave_vulners
   export GEMINI_API_KEY=sua_chave_gemini
   export CHATGPT_API_KEY=sua_chave_chatgpt
   export LLAMA_API_KEY=sua_chave_llama
   ```

2. Alternativamente, você pode passar as chaves de API como argumentos ao executar o script.

## Uso

### Argumentos de Linha de Comando

- `--source`: Seleciona o provedor de IA para categorização (`gemini`, `chatgpt`, `llama`, `combined`, `none`).
- `--data-source`: Seleciona a fonte de dados para vulnerabilidades (`nvd`, `vulners`, `both`).
- `--gemini-key`: Chave de API para Gemini.
- `--chatgpt-key`: Chave de API para ChatGPT.
- `--llama-key`: Chave de API para Llama.
- `--vulners-key`: Chave de API para Vulners.
- `--export-format`: Formato de exportação (`csv`, `json`).
- `--output-file`: Nome do arquivo de saída.
- `--search-params`: Parâmetros de busca para vulnerabilidades.
- `--search-file`: Caminho para um arquivo contendo parâmetros de busca.

### Exemplo de Comando

**Com IA e múltiplas fontes:**

```bash
python src/main.py --source combined --data-source both --search-params "OpenDDS" "RTI Connext DDS" --gemini-key <SUA_CHAVE_GEMINI> --chatgpt-key <SUA_CHAVE_CHATGPT> --llama-key <SUA_CHAVE_LLAMA> --vulners-key <SUA_CHAVE_VULNERS> --export-format csv --output-file vulnerabilidades.csv
```

**Sem IA, usando a fonte do NVD:**

```bash
python src/main.py --source none --data-source nvd --search-params "OpenDDS" --export-format csv --output-file vulnerabilidades.csv
```

**Sem IA, usando a fonte do NVD e VULNERS:**

```bash
python src/main.py --source none --data-source both --vulners-key <SUA_CHAVE_VULNERS> --search-params "OpenDDS" --export-format csv --output-file vulnerabilidades-both.csv
```

**Usando arquivo contendo os parâmetros de busca busca:**

Crie um arquivo `search_terms.txt`:

```
"OpenDDS"
"RTI Connext"
"Eclipse Cyclone DDS"
```

Execute:

```bash
python src/main.py --source gemini --data-source vulners --search-file search_terms.txt --vulners-key <SUA_CHAVE_VULNERS> --gemini-key <SUA_CHAVE_OPENAI> --output-file vulnerabilidades-both.csv
```

## Docker

Você também pode executar o script usando Docker.

# Dockerfile

```yaml
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

# Construir e Executar o Contêiner Docker

1. **Construir a imagem:**

```bash
docker build -t ddsbuilder .
```

2. **Executar o container usando IA para categorização:**

```bash
docker run ddsbuilder python src/main.py --source combined --data-source both --vulners-key <SUA_CHAVE_VULNERS> --gemini-key <SUA_CHAVE_GEMINI> --chatgpt-key <SUA_CHAVE_OPENAI> --llama-key <SUA_CHAVE_OPENAI> --export-format csv --output-file vulnerabilidades.csv --search-params "OpenDDS"
```

3. **Executar o container sem usar IA para categorização:**

```bash
docker run --source none --data-source nvd --export-format csv --output-file vulnerabilidades.csv --search-params "OpenDDS"
```

## Licença

Este projeto está licenciado sob a Licença GNU - veja o arquivo LICENSE para mais detalhes.
