import requests
import json
import os
import time

# extractor para nvd from vulners.com
def collect_data(search_params):
    vulnerabilities = []
    for param in search_params:
            nvd_response = get_data(param)
            if nvd_response and 'vulnerabilities' in nvd_response:
                vulnerabilities.extend(nvd_response['vulnerabilities'])
                print(f"Found {len(nvd_response['vulnerabilities'])} NVD vulnerabilities")
    return vulnerabilities

#  Função para buscar dados de vulnerabilidade da API NVD    
def get_data(keyword):
    """Fetches vulnerability data from the NVD API"""
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'keywordSearch': keyword,
    
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
