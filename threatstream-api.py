import requests
import sys

# ==== EXECUÇÃO VIA ARGUMENTOS ====
if len(sys.argv) != 3:
    print("Uso correto: python3 threatstream-api.py <username> <apikey>")
    sys.exit(1)

USERNAME = sys.argv[1]
API_KEY = sys.argv[2]

BASE_URL = 'https://api.threatstream.com/api/v1/threat_model_search/'

HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def buscar_threat_models(limit=5, offset=0):
    params = {'limit': limit, 'offset': offset}

    try:
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()

        dados = response.json()
        objetos = dados.get('objects', [])

        if not objetos:
            print("Nenhum resultado encontrado.")
        else:
            print(f"✅ {len(objetos)} modelos de ameaça encontrados:")
            for obj in objetos:
                print(f"- ID: {obj.get('id')} | Nome: {obj.get('name')}")

        return objetos

    except requests.exceptions.HTTPError as http_err:
        print(f"Erro HTTP: {http_err} - {response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Erro de conexão: {req_err}")
    except Exception as e:
        print(f"Erro inesperado: {e}")

    return []

if __name__ == '__main__':
    buscar_threat_models()
