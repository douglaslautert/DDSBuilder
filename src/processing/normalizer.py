from data_sources import nvd_extractor
import output.csv_exporter as csv_exporter
import re

FIELDS = "*"  # Definido para uso na consulta

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

def normalize_old_data(vulnerability, description_without_punct, truncated_description):
    source = vulnerability.get('_source', {})
    normalized = {
        'id': source.get('id') or vulnerability.get('id'),
        'title': source.get('title') or vulnerability.get('title', 'No Title'),
        'description': truncated_description,
        'description_normalized': description_without_punct,
        'published': source.get('published') or vulnerability.get('published', ''),
        'cvss_score': source.get('cvss', {}).get('score') if source.get('cvss') else vulnerability.get('cvss', {}).get('score', ''),
        'severity': source.get('cvss', {}).get('severity') if source.get('cvss') else vulnerability.get('cvss', {}).get('severity', ''),
        'source': vulnerability.get('source', 'NVD')
    }
    return normalized

def normalize_data(vulnerability, description_without_punct, truncated_description):
    """Normalize vulnerability data from different sources."""
    if 'cve' in vulnerability:
        # NVD data structure
        cve = vulnerability['cve']
        
        # Extract CVSS score and severity from metrics
        cvss_score = None
        severity = None
        published_date = cve.get('published')  # Get published date from cve object
        
        if 'metrics' in cve:
            metrics = cve['metrics']
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                primary_metric = next(
                    (m for m in metrics['cvssMetricV31'] if m.get('type') == 'Primary'),
                    metrics['cvssMetricV31'][0]
                )
                cvss_score = primary_metric['cvssData'].get('baseScore')
                severity = primary_metric['cvssData'].get('baseSeverity')
            # Fallback to CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                primary_metric = next(
                    (m for m in metrics['cvssMetricV2'] if m.get('type') == 'Primary'),
                    metrics['cvssMetricV2'][0]
                )
                cvss_score = primary_metric['cvssData'].get('baseScore')
                severity = primary_metric.get('baseSeverity')

        normalized = {
            'id': cve.get('id'),
            'title': next((desc.get('value') for desc in cve.get('descriptions', []) 
                          if desc.get('lang') == 'en'), 'No Title'),
            'description': truncated_description,
            'description_normalized': description_without_punct,
            'published': published_date,  # Use published date from cve
            'cvss_score': cvss_score,
            'severity': severity,
            'source': 'NVD'
        }
    else:
        # Vulners or other data structure
        source = vulnerability.get('_source', {})
        normalized = {
            'id': source.get('id') or vulnerability.get('id'),
            'title': source.get('title') or vulnerability.get('title', 'No Title'),
            'description': truncated_description,
            'description_normalized': description_without_punct,
            'published': source.get('published') or vulnerability.get('published', ''),
            'cvss_score': source.get('cvss', {}).get('score'),
            'severity': source.get('cvss', {}).get('severity'),
            'source': 'Vulners' if '_source' in vulnerability else vulnerability.get('source', 'Unknown')
        }

    return normalized

def filter_vulnerabilities(vulnerabilities, **criteria):
    """
    Filtra vulnerabilidades baseado em critérios arbitrários.
    """
    filtered = []
    for vuln in vulnerabilities:
        if all(vuln.get(field) == value for field, value in criteria.items()):
            filtered.append(vuln)
    return filtered

def get_vulners_data(vulnerability, fields=None):
    """
    Retorna os dados da vulnerabilidade com os campos especificados.
    """
    data = normalize_old_data(vulnerability,
                          vulnerability.get("description", ""),
                          vulnerability.get("description", ""))
    if fields:
        return {key: data.get(key) for key in fields}
    return data

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

def normalize_vulnerability(vuln):
    """
    Returns a normalized vulnerability dictionary.
    Se o dado recebido não for um dicionário, retorna None para ignorá-lo.
    """
    if not isinstance(vuln, dict):
        print("Vulnerabilidade ignorada (não é dicionário):", vuln)
        return None

    return {
        "id": vuln.get("id") or vuln.get("CVE") or f"{vuln.get('source','')}_{vuln.get('title','')}",
        "title": vuln.get("title", "No Title"),
        "description": vuln.get("description", ""),
        "vendor": vuln.get("vendor", "Unknown"),
        "published": vuln.get("published", ""),
        "cvss_score": vuln.get("cvss_score", ""),
        "severity": vuln.get("severity", ""),
        "source": vuln.get("source", "")
    }

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
    return all_vulnerabilities  # Retorna os dados normalizados

if __name__ == '__main__':
    vulns = normalizer()
    import output.csv_exporter as csv_exporter
    import output.json_exporter as json_exporter
    csv_exporter.write_to_csv(vulns, 'output.csv')
    json_exporter.write_to_json(vulns, 'output.json')
