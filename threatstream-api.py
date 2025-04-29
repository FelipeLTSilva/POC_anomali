import requests
import sys

# Espera 3 argumentos: <endpoint> <username> <apikey>
if len(sys.argv) != 4:
    print("Uso correto: python3 threatstream-api.py <endpoint> <username> <apikey>")
    sys.exit(1)

ENDPOINT = sys.argv[1]
USERNAME = sys.argv[2]
API_KEY = sys.argv[3]

BASE_URL = f'https://api.threatstream.com/api/v1/{ENDPOINT}/'

HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def buscar(limit=5, offset=0):
    params = {'limit': limit, 'offset': offset}
    try:
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        dados = response.json()
        objetos = dados.get('objects', [])

        if not objetos:
            print("Nenhum resultado encontrado.")
        else:
            print(f"✅ {len(objetos)} resultados encontrados:")
            for obj in objetos:
                print(f"- ID: {obj.get('id')} | Nome: {obj.get('name', 'Sem nome')}")

    except requests.exceptions.HTTPError as http_err:
        print(f"Erro HTTP: {http_err} - {response.text}")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == '__main__':
    buscar()
