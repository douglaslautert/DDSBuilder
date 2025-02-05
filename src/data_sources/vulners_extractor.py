import requests
import json
import re
import os

FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]

def get_vulners_data(query, skip=0):
    """Searches for vulnerabilities using the Vulners API."""
    base_url = "https://vulners.com/api/v3/search/search"
    api_key = os.getenv("VULNERS_API_KEY")
    data = {
        'query': query,
        'fields': FIELDS,
        'skip': skip,
        'apiKey': api_key
    }
    try:
        response = requests.post(base_url, data=json.dumps(data))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"Other error occurred: {err}")
    return {}

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