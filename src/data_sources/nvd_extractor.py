import requests
import json
import os
import time
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


def get_nvd_data(keyword, start_index=0, results_per_page=40):
    """Fetches vulnerability data from the NVD API"""
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'keywordSearch': keyword,
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get(base_url, params=params, headers=headers)
    if response.status_code == 403:
        print(f"Rate limit exceeded or access forbidden for keyword: {keyword}")
        time.sleep(60)  # Wait for 1 minute before retrying
        response = requests.get(base_url, params=params, headers=headers)
    response.raise_for_status()
    return response.json()


def fetch_all_vulnerabilities(keyword):
    """Fetches all vulnerabilities for a given keyword, respecting rate limits"""
    all_vulnerabilities = []
    start_index = 0
    results_per_page = 40
    while True:
        data = get_nvd_data(keyword, start_index=start_index, results_per_page=results_per_page)
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            break
        all_vulnerabilities.extend(vulnerabilities)
        start_index += results_per_page
        total_results = data.get('totalResults', 0)
        if start_index >= total_results:
            break
        time.sleep(6)  # Sleep to respect rate limits (5 requests per 30 seconds)
    return all_vulnerabilities