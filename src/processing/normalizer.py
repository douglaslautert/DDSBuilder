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
def filter_vulnerabilities(vulnerabilities, id=None, title=None, description=None, vendor=None, published=None, cvss_score=None, severity=None, source=None):
    def matches_criteria(cve, id, title, description, vendor, published, cvss_score, severity, source):
        cve_id = cve.get('id')
        cve_description = next((desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'), '')
        cve_published = cve.get('published')
        cve_source = cve.get('sourceIdentifier')  # Aqui está o erro, vamos corrigir para cve.get('source')
        cve_metrics = cve.get('metrics', {})
        cve_cvss_score = next((metric['cvssData']['baseScore'] for metric in cve_metrics.get('cvssMetricV31', [])), None)
        cve_severity = next((metric['cvssData']['baseSeverity'] for metric in cve_metrics.get('cvssMetricV31', [])), None)
        cve_vendor = next((config['cpeMatch'][0]['criteria'].split(':')[3] for config in cve.get('configurations', [{}])[0].get('nodes', [{}])), '')

        return (not id or id == cve_id) and \
               (not title or title in cve_description) and \
               (not description or description in cve_description) and \
               (not vendor or vendor == cve_vendor) and \
               (not published or published == cve_published) and \
               (not cvss_score or cvss_score == cve_cvss_score) and \
               (not severity or severity == cve_severity) and \
               (not source or source == cve_source)

    return [vuln['cve'] for vuln in vulnerabilities if matches_criteria(vuln['cve'], id, title, description, vendor, published, cvss_score, severity, source)]

def extract_vulners_data(vulnerability):
    """Extracts relevant information from a Vulners vulnerability entry, handling encoding."""
    description = vulnerability.get('_source', {}).get('description', '')
    if description:
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



def fetch_vulnerabilities_vulners():
    print(f"Fetching vulnerabilities for vulners...")
    all_vulnerabilities = []
    search_query = ' OR '.join([f'"{vendor}"' for vendor in VENDORS]) + ' "data distribution service"'
    skip = 0

    while True:
        data = nvd_extractor.get_vulners_data(search_query, FIELDS, skip)
        if data is None:
            print(f"Erro: A API do Vulners retornou None para a consulta: {search_query}")
            break

        new_vulnerabilities = [extract_vulners_data(cve) for cve in data['data']['search']]
        all_vulnerabilities.extend(new_vulnerabilities)
        total = data['data']['total']
        skip += len(data['data']['search'])

        if skip >= total:
            break

    return all_vulnerabilities

def fetch_vulnerabilities_nvd():
    all_vulnerabilities = []
    for vendor in VENDORS:
        print(f"Fetching vulnerabilities for {vendor}...")
        vulnerabilities = nvd_extractor.fetch_all_vulnerabilities(vendor)
        if vulnerabilities:
            filtered_vulnerabilities = [extract_vulners_data(cve) for cve in vulnerabilities]
            all_vulnerabilities.extend(filtered_vulnerabilities)
    return all_vulnerabilities      

def normalizer():
    tam = 30
    opcoes = {
        "1": "gemini",
        "2": "chatGPT",
        "3": "llama",
        "0": "sair"
    }
    all_vulnerabilities = []
    all_vulnerabilities = fetch_vulnerabilities_vulners()
    all_vulnerabilities.extend(fetch_vulnerabilities_nvd())
    while True:
        print(f"+{'-'*tam}+")
        print(f"|{'Menu':^{tam}}|")
        print(f"+{'-'*tam}+")
        for k, v in opcoes.items():
            print(f"|{f'{k} - {v}':{tam}}|")
        print(f"+{'-'*tam}+")
        op = input()
        if op not in opcoes:
            print("Opção inválida")
            continue
        if(op == "0"):
            break    
        if(op == "1"):
            csv_exporter.write_to_csv_from_gemini(all_vulnerabilities, CSV_OUTPUT_FILE)
        if(op == "2"):
            csv_exporter.write_to_csv_from_gpt(all_vulnerabilities, CSV_OUTPUT_FILE)
        if(op == "3"):
            csv_exporter.write_to_csv_from_llama(all_vulnerabilities, CSV_OUTPUT_FILE)
