import requests
import json
import os

# extractor para nvd from vulners.com
def get_vulners_data(query, fields, skip=0):
    """Searches for vulnerabilities using the Vulners API."""
    base_url = "https://vulners.com/api/v3/search/search"
    data = {
        'query': query,
        'fields': fields,
        'skip': skip,
        'apiKey': os.environ["VULNERS_API_KEY"] 
    }
    response = requests.post(base_url, data=json.dumps(data))
    response.raise_for_status()
    return response.json()