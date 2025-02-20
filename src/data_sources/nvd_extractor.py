import requests
import time
from .data_source import DataSourceBase

class NvdExtractor(DataSourceBase):
    def collect_data(self, search_params):
        vulnerabilities = []
        for param in search_params:
            print(f"Collecting NVD data for search parameter: {param}")
            nvd_response = self.get_nvd_data(param)
            if nvd_response and 'vulnerabilities' in nvd_response:
                vulnerabilities.extend(nvd_response['vulnerabilities'])
                print(f"Found {len(nvd_response['vulnerabilities'])} NVD vulnerabilities for {param}")
            else:
                print(f"No vulnerabilities found for {param}")
            time.sleep(1)
        return vulnerabilities

    def get_nvd_data(self, keyword):
        base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        params = {'keywordSearch': keyword}
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"Sending request to NVD API with keyword: {keyword}")
        response = requests.get(base_url, params=params, headers=headers)
        print(f"NVD API response status code: {response.status_code}")
        if response.status_code == 403:
            print(f"Rate limit exceeded or access forbidden for keyword: {keyword}")
            time.sleep(5)
            response = requests.get(base_url, params=params, headers=headers)
            print(f"NVD API response status code after retry: {response.status_code}")
        response.raise_for_status()
        return response.json()