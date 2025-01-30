from data_sources import nvd_extractor
import output.csv_exporter as csv_exporter
import re

CSV_OUTPUT_FILE = "dataset/dds_vulnerabilities_AI.csv"
FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]
VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds"
]
# filter vulnerabilities from vulners.com
def filtro_vulner(vulnerability, description_without_punct, truncated_description):
    vendor = 'UNKNOWN'
    for v in VENDORS:
        v_without_punct = re.sub(r'[^\w\s]', '', v).lower()
        if v_without_punct in description_without_punct:
            vendor = v
            break
        
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

# extract from vulners.com vulnerabilities 
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
    
    return filtro_vulner(vulnerability, description_without_punct, truncated_description) 



def normalizer():
    all_vulnerabilities = []
    search_query = ' OR '.join([f'"{vendor}"' for vendor in VENDORS]) + ' "data distribution service"'
    skip = 0
    while True:
        data = nvd_extractor.get_vulners_data(search_query, FIELDS, skip)
        # Verificar se 'data' não é None
        if data is not None:
            new_vulnerabilities = [extract_vulners_data(cve) for cve in data['data']['search']]
            all_vulnerabilities.extend(new_vulnerabilities)
            total = data['data']['total']
            skip += len(data['data']['search'])
            if skip >= total:
                break
        else:
            print(f"Erro: A API do Vulners retornou None para a consulta: {search_query}")
            break
    
    for vendor in VENDORS:
        print(f"Fetching vulnerabilities for {vendor}...")
        vulnerabilities = nvd_extractor.fetch_all_vulnerabilities(vendor)
        all_vulnerabilities.extend(vulnerabilities)
    
    
    choice = int(input("Digit 1 for gemini or 2 for chatGPT or 3 for llama: "))
    while(choice < 1 or choice > 3):
        choice = int(input("Digit 1 for gemini or 2 for chatGPT or 3 for llama: "))
    
    if(choice == 1):
        csv_exporter.write_to_csv_from_gemini(all_vulnerabilities, CSV_OUTPUT_FILE)
    else: 
        if(choice == 2):
            csv_exporter.write_to_csv_from_gpt(all_vulnerabilities, CSV_OUTPUT_FILE)
        else:
            csv_exporter.write_to_csv_from_llama(all_vulnerabilities, CSV_OUTPUT_FILE)
