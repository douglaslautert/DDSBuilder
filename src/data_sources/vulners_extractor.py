import requests
import json
import re
import os

FIELDS = ["bulletinFamily", "cvss", "description", "id", "lastseen", "modified", "published", "title", "type", "vhref", "viewCount", "href", "enchantments", "bounty", "sourceData", "cvss3", "cvss2", "epss"]
def collect_data(search_params):
    vulnerabilities = []
    for param in search_params:
            vulners_response = get_data(param)
            if vulners_response and 'data' in vulners_response and 'search' in vulners_response['data']:
                vulners_vulns = vulners_response['data']['search']
                vulnerabilities.extend(vulners_vulns)
                print(f"Found {len(vulners_vulns)} Vulners vulnerabilities")
                vulnerabilities.extend(vulners_response['data']['search'])
    return vulnerabilities
            
def get_data(query, skip=0):
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
