import re

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

# filter vulnerabilities from NVD
def filtro_nvd(vulnerability, description_without_punct, truncated_description):
    vendor = 'UNKNOWN'
    for v in VENDORS:
        v_without_punct = re.sub(r'[^\w\s]', '', v).lower()
        if v_without_punct in description_without_punct:
            vendor = v
            break
        
    return {
        'id': vulnerability.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
        'title': vulnerability.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value'),
        'description': truncated_description,
        'vendor': vendor,
        'published': vulnerability.get('publishedDate'),
        'cvss_score': vulnerability.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore'),
        'severity': vulnerability.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity'),
        'source': 'NVD'
    }

# filter vulnerabilities from GitHub
def filtro_github(vulnerability, description_without_punct, truncated_description):
    vendor = 'UNKNOWN'
    for v in VENDORS:
        v_without_punct = re.sub(r'[^\w\s]', '', v).lower()
        if v_without_punct in description_without_punct:
            vendor = v
            break
        
    return {
        'id': vulnerability.get('id'),
        'title': vulnerability.get('title'),
        'description': truncated_description,
        'vendor': vendor,
        'published': vulnerability.get('published_at'),
        'cvss_score': vulnerability.get('cvss_score'),
        'severity': vulnerability.get('severity'),
        'source': 'GitHub'
    }