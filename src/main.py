import os
from data_sources import nvd_extractor
import processing.extractor as extractor
import output.csv_exporter as csv_exporter

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
# Define a chave de API do VULNERS como uma variável de ambiente
os.environ["VULNERS_API_KEY"] = VULNERS_API_KEY

FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]
VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds"
]

def main():
    """Orchestrates the vulnerability search and data extraction process."""
    all_vulnerabilities = []
    search_query = ' OR '.join([f'"{vendor}"' for vendor in VENDORS]) + ' "data distribution service"'
    skip = 0
    while True:
        data = nvd_extractor.get_vulners_data(search_query, FIELDS, skip)
        # Verificar se 'data' não é None
        if data is not None:
            new_vulnerabilities = [extractor.extract_vulners_data(cve) for cve in data['data']['search']]
            all_vulnerabilities.extend(new_vulnerabilities)
            total = data['data']['total']
            skip += len(data['data']['search'])
            if skip >= total:
                break
        else:
            print(f"Erro: A API do Vulners retornou None para a consulta: {search_query}")
            break
    choice = int(input("Digit 1 for gemini or 2 for chat-GPT : "))
    while(choice < 1 or choice > 2):
        choice = int(input("Digit 1 for gemini or 2 for chat-GPT : "))
    
    if(choice == 1):
        csv_exporter.write_to_csv_from_gemini(all_vulnerabilities, CSV_OUTPUT_FILE)
    else:
        csv_exporter.write_to_csv_from_gpt(all_vulnerabilities, CSV_OUTPUT_FILE)
    
    print(f"Vulnerability data saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()