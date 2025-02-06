import requests
import json
import os
import time
# extractor para nvd from vulners.com
def get_vulners_data(search_query, fields, skip):
    # Implementação dummy para testes
    if skip > 0:
        return {'data': {'search': [], 'total': 1}}
    return {
        'data': {
            'search': [{
                '_source': {
                    'id': 'V1',
                    'title': 'Sample Vuln from Vulners',
                    'description': 'Allows remote code execution',
                    'published': '2021-01-01',
                    'cvss': {'score': 8.5, 'severity': 'HIGH'}
                }
            }],
            'total': 1
        }
    }

def get_nvd_data(keyword):
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


def fetch_all_vulnerabilities(vendor):
    # Implementação dummy: retorna uma vulnerabilidade para o vendor
    return [{
        'cve': {
            'id': f'NVD_{vendor}_001',
            'descriptions': [{'lang': 'en', 'value': f'{vendor} vulnerability description'}],
            'published': '2021-06-01',
            'sourceIdentifier': 'NVD',
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 5.0,
                        'baseSeverity': 'MEDIUM'
                    }
                }]
            },
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': f"cpe:2.3:o:{vendor}:product:version"
                    }]
                }]
            }]
        }
    }]