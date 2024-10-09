# DDS Vulnerability Scraper with Google Gemini

Este script Python coleta informações de vulnerabilidades relacionadas ao DDS (Data Distribution Service) da API do Vulners e usa o Google Gemini para categorizar cada vulnerabilidade em uma categoria CWE.


## Pré-requisitos

- Você precisará de uma chave de API do Vulners. Obtenha uma em: https://vulners.com/
- Você precisará de uma chave de API do Google Gemini. Crie uma em: https://developers.google.com/generative-ai
- Python 3.7 ou superior: Certifique-se de ter o Python instalado. Você pode baixá-lo aqui: https://www.python.org/downloads/


## Configuração

- Substitua as Chaves de API: No arquivo scrap_gemini.py, substitua os espaços reservados YOUR_GEMINI_API_KEY e YOUR_VULNERS_API_KEY pelas suas chaves de API reais.
- Defina a Variável de Ambiente: Defina a variável de ambiente GOOGLE_API_KEY com sua chave de API do Gemini. Você pode fazer isso diretamente no seu terminal antes de executar o script:




## Execução

- Salve o script: Salve o código fornecido como scrap_gemini.py.
- Execute o script: Abra seu terminal e navegue até o diretório onde você salvou o script. Em seguida, execute o script:
   
    ~~~
    python dds_vulners_collect.py
    ~~~


## Saída

O script gerará um arquivo CSV chamado dds_vulnerabilities_gemini.csv contendo as seguintes informações para cada vulnerabilidade encontrada:



- id: ID da vulnerabilidade (por exemplo, CVE-2024-1234).

- title: Título da vulnerabilidade.

- description: Descrição da vulnerabilidade.

- vendor: Vendor afetado pela vulnerabilidade.

- published: Data de publicação da vulnerabilidade.

- cvss: Pontuação CVSS da vulnerabilidade.

- severity: Gravidade da vulnerabilidade (por exemplo, Alta, Média, Baixa).

- cwe_category: Categoria CWE atribuída pelo Google Gemini.

- cwe_explanation: Explicação da categoria CWE fornecida pelo Google Gemini.

- source: Fonte dos dados da vulnerabilidade (Vulners).
