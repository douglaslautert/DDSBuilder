import requests
import asyncio
from .data_source import DataSourceBase

class NvdExtractor(DataSourceBase):
    async def collect_data(self, search_params):
        vulnerabilities = []
        for param in search_params:
            print(f"Collecting NVD data for search parameter: {param}")
            nvd_response = await self.get_nvd_data(param)  # Adicione await aqui
            if nvd_response and 'vulnerabilities' in nvd_response:
                for vuln in nvd_response['vulnerabilities']:
                    vulnerabilities.append(vuln)
                print(f"Found {len(nvd_response['vulnerabilities'])} NVD vulnerabilities for {param}")
            else:
                print(f"No vulnerabilities found for {param}")
        return vulnerabilities

    async def get_nvd_data(self, keyword):
        base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        params = {'keywordSearch': keyword}
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"\nSending request to NVD API with keyword: {keyword}")
        response = requests.get(base_url, params=params, headers=headers)
        print(f"NVD API response status code: {response.status_code}")
        if response.status_code == 403:
            print(f"Rate limit exceeded or access forbidden for keyword: {keyword}")
            await asyncio.sleep(5)
            response = requests.get(base_url, params=params, headers=headers)
            print(f"NVD API response status code after retry: {response.status_code}")
        response.raise_for_status()
        return response.json()

    def normalize_data(self, vulnerability):
        cve = vulnerability.get('cve', {})
        metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
        return {
            'id': cve.get('id'),
            'description': next((desc.get('value') for desc in cve.get('descriptions', []) if desc.get('lang') == 'en'), ''),
            'published': cve.get('published'),
            'cvss_score': metrics.get('baseScore'),
            'severity': metrics.get('baseSeverity'),
            'source': 'nvd'
        }