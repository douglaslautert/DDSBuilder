import requests

def fetch_github_vulnerabilities(api_url, params=None):
    try:
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()  # Lança exceção para status de erro HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro na chamada à API: {e}")
        # Pode-se optar por propagar a exceção ou retornar um dicionário vazio
        return {}
