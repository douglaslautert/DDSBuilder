import requests
import csv
import json
import re
from datetime import datetime as dt
from requests.auth import HTTPBasicAuth
import google.generativeai as genai
import os
import time
from openai import OpenAI

# ***** CONFIGURATION *****
GEMINI_API_KEY = "GEMINI_API_KEY" # Replace with your Gemini API key
CHAT_API_KEY = "CHAT_API_KEY" # Replace with your Chat-GPT API Key
VULNERS_API_KEY = "VULNERS_API_KEY" # Replace with your actual Vulners API key
CSV_OUTPUT_FILE = "dataset/dds_vulnerabilities_AI.csv" # Change the output file name
# ***** END CONFIGURATION *****

# Define a chave de API do Gemini como uma variável de ambiente
os.environ["GOOGLE_API_KEY"] = GEMINI_API_KEY
# Define a chave de API do Chat-GPT como uma variável de ambiente
os.environ["CHAT_API_KEY"] = CHAT_API_KEY

# Safety configuration for Gemini
safe = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]

VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds"
]

FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]

def get_vulners_data(query, fields, skip=0):
    """Searches for vulnerabilities using the Vulners API."""
    base_url = "https://vulners.com/api/v3/search/search"
    data = {
        'query': query,
        'fields': fields,
        'skip': skip,
        'apiKey': VULNERS_API_KEY 
    }
    response = requests.post(base_url, data=json.dumps(data))
    response.raise_for_status()
    return response.json()

def extract_vulners_data(vulnerability):
    """Extracts relevant information from a Vulners vulnerability entry, handling encoding."""
    description = vulnerability.get('_source', {}).get('description')
    description = description.encode('utf-8', errors='replace').decode('utf-8')
    max_length = 500
    if len(description) > max_length:
        key_phrases = ["allows", "to cause", "via", "in", "component"]
        extracted_parts = []
        for sentence in description.split(". "):
            for phrase in key_phrases:
                if phrase in sentence:
                    extracted_parts.append(sentence)
                    break
        truncated_description = ". ".join(extracted_parts[:2]) + "..."
    else:
        truncated_description = description

    description_without_punct = re.sub(r'[^\w\s]', '', truncated_description).lower()

    vendor = 'UNKNOWN'
    for v in VENDORS:
        v_without_punct = re.sub(r'[^\w\s]', '', v).lower()
        if v_without_punct in description_without_punct:
            vendor = v
            break

    cvss_data = vulnerability.get('_source', {})
    return {
        'id': vulnerability.get('_source', {}).get('id'),
        'title': vulnerability.get('_source', {}).get('title'),
        'description': truncated_description,
        'vendor': vendor,
        'published': vulnerability.get('_source', {}).get('published'),
        'cvss_score': vulnerability.get('_source', {}).get('cvss', {}).get('score'), # vulners cvss is on score
        'severity': vulnerability.get('_source', {}).get('cvss', {}).get('severity'), # vulners severity is on severity
        'source': 'Vulners'
    }

def categorize_vulnerability_gpt(description):
    """Categorizes the vulnerability and extracts cause, impact, and vendor using Chat GPT."""
    client = OpenAI(
    api_key = os.environ["CHAT_API_KEY"]
    )

    prompt = f"""
    You are a security expert.
    Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
    Provide the CWE ID, a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
    ```
    """
    time.sleep(1)

    completion = client.chat.completions.create(
    model="gpt-4o-mini",
    store=True,
    messages=[
            {"role": "user", "content": prompt}])

    print(completion.choices[0].message.content);

    text_part = completion.choices[0].message.content

    # Extrair o JSON usando expressão regular
    match = re.search(r'``[`json\n(.*?)\n`](command:_github.copilot.openSymbolFromReferences?%5B%22%22%2C%5B%7B%22uri%22%3A%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2FMESTRADO%2FDDS%2FSCRAP_DDS%2Fscrap_generate_dataset.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22pos%22%3A%7B%22line%22%3A2%2C%22character%22%3A7%7D%7D%5D%2C%224136289f-5814-4b75-9d6f-56e9b5bfd10d%22%5D "Go to definition")``', text_part, re.DOTALL)
    if match:
                    json_str = match.group(1)
                    
                    try:
                        result = json.loads(json_str, strict=False)
                        cwe_category = result.get('cwe_category', 'Unknown')
                        explanation = result.get('explanation', 'Could not categorize vulnerability')
                        vendor = result.get('vendor', 'Unknown')
                        cause = result.get('cause', 'Unknown')
                        impact = result.get('impact', 'Unknown')
                        return [(cwe_category, explanation, vendor, cause, impact)]
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON from Chat-GPT response: {json_str}")
                        return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
    else:
                    print(f"Could not find JSON in Chat-GPT response: {text_part}")
                    return [("UNKNOWN", "Could not find JSON in Gemini response", "Unknown", "Unknown", "Unknown")]


def categorize_vulnerability(description):
    """Categorizes the vulnerability and extracts cause, impact, and vendor using Google Gemini."""
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    model = genai.GenerativeModel('gemini-1.5-pro')

    prompt = f"""
    You are a security expert.
    Categorize the following vulnerability description into a CWE category, identify the vendor, and extract the cause and impact of the vulnerability.
    Provide the CWE ID, a brief explanation, the vendor name, the cause of the vulnerability, and its impact.

    Description:
    ```
    {description}
    ```

    Output:
    ```json
    {{"cwe_category": "CWE-ID", "explanation": "Brief Explanation of the CWE", "vendor": "Vendor Name", "cause": "Cause of the Vulnerability", "impact": "Impact of the Vulnerability"}}
    ```
    """
    time.sleep(1)

    try:
        response = model.generate_content(prompt, safety_settings=safe)
        print(response)

        if response._result.candidates:
            if response._result.candidates[0].content.parts:
                text_part = response._result.candidates[0].content.parts[0].text

                # Extrair o JSON usando expressão regular
                match = re.search(r'``[`json\n(.*?)\n`](command:_github.copilot.openSymbolFromReferences?%5B%22%22%2C%5B%7B%22uri%22%3A%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2FMESTRADO%2FDDS%2FSCRAP_DDS%2Fscrap_generate_dataset.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22pos%22%3A%7B%22line%22%3A2%2C%22character%22%3A7%7D%7D%5D%2C%224136289f-5814-4b75-9d6f-56e9b5bfd10d%22%5D "Go to definition")``', text_part, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    
                    try:
                        result = json.loads(json_str, strict=False)
                        cwe_category = result.get('cwe_category', 'Unknown')
                        explanation = result.get('explanation', 'Could not categorize vulnerability')
                        vendor = result.get('vendor', 'Unknown')
                        cause = result.get('cause', 'Unknown')
                        impact = result.get('impact', 'Unknown')
                        return [(cwe_category, explanation, vendor, cause, impact)]
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON from Gemini response: {json_str}")
                        return [("UNKNOWN", "Error categorizing vulnerability", "Unknown", "Unknown", "Unknown")]
                else:
                    print(f"Could not find JSON in Gemini response: {text_part}")
                    return [("UNKNOWN", "Could not find JSON in Gemini response", "Unknown", "Unknown", "Unknown")]

            else:
                print(f"Gemini response has no parts: {response.result}")
                return [("UNKNOWN", "Gemini response has no parts", "Unknown", "Unknown", "Unknown")]
        else:
            print(f"Gemini returned no candidates: {response.result}")
            return [("UNKNOWN", "Gemini returned no candidates", "Unknown", "Unknown", "Unknown")]

    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return [("UNKNOWN", "Error calling Gemini API", "Unknown", "Unknown", "Unknown")]

def write_to_csv(data, filename):
    """Writes the extracted vulnerability data to a CSV file,
    avoiding duplicates and using Gemini for categorization.
    """
    fieldnames = ['id', 'title', 'description', 'vendor', 'published',
                  'cvss_score', 'severity', 'cwe_category', 'cwe_explanation', 'cause', 'impact', 'source']
    existing_vulnerabilities = {}

    # Tente ler vulnerabilidades existentes do arquivo
    try:
        with open(filename, 'r', encoding="latin1") as csvfile:  # Use latin1 aqui
            reader = csv.DictReader(csvfile)
            # Verificar se o arquivo está vazio
            if reader.fieldnames:
                for row in reader:
                    # Lidar com a possibilidade da chave 'id' não existir
                    try:
                        existing_vulnerabilities[row['title']] = row['id'] 
                    except KeyError:
                        print(f"Aviso: A linha não possui a chave 'id': {row}")
                        # existing_vulnerabilities[row['title']] = "ID_DESCONHECIDO"
    except FileNotFoundError:
        pass

    with open(filename, 'a', newline='', encoding="utf-8") as csvfile:  # UTF-8 para a escrita
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Escrever o cabeçalho apenas se o arquivo estiver vazio
        if len(existing_vulnerabilities) == 0:
            writer.writeheader()

        for item in data:
            # Verificar se a vulnerabilidade já existe com base no título
            if item['title'] not in existing_vulnerabilities:
                vulnerability_data = categorize_vulnerability_gpt(item['description'])
                # Filtrar vulnerabilidades que não são referentes a DDS e aos vendors especificados
                if any(vendor.lower() in item['description'].lower() for vendor in VENDORS):
                    for cwe_category, cwe_explanation, vendor, cause, impact in vulnerability_data:
                        if vendor.strip().upper() != 'UNKNOWN':
                            # Atribuir os valores ao dicionário 'item'
                            item['cwe_category'] = cwe_category
                            item['cwe_explanation'] = cwe_explanation
                            item['vendor'] = vendor
                            item['cause'] = cause
                            item['impact'] = impact

                            writer.writerow(item)
                            existing_vulnerabilities[item['title']] = item['id'] 

