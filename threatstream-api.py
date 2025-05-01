import requests
import sys
import json

# Configurações iniciais
ENDPOINT = sys.argv[1]
USERNAME = sys.argv[2]
API_KEY = sys.argv[3]

BASE_URL = 'https://api.threatstream.com/api/v1'
HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Palavras-chave para correspondência
KEYWORDS = ['network service scanning', 'process injection', 't1046', 't1055']
INTEL_MODELS = {'ttp'}

# Função para verificar correspondência de palavras-chave
def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

# Função para buscar modelos de ameaça
def buscar_threat_models(endpoint, limit=1000, offset=0):
    resultados = []
    while True:
        params = {'limit': limit, 'offset': offset}
        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()
        data = response.json()
        objetos = data.get('objects', [])
        if not objetos:
            break
        for obj in objetos:
            name = obj.get('name', '')
            model_type = obj.get('model_type', '').lower()
            if model_type in INTEL_MODELS and keyword_match(name):
                resultados.append(obj)
        if not data.get('next'):
            break
        offset += limit
    return resultados

# Execução principal
if __name__ == '__main__':
    try:
        resultados = buscar_threat_models(ENDPOINT)
        print(json.dumps(resultados, indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão ou HTTP: {e}")
    except Exception as e:
        print(f"Erro inesperado: {e}")
