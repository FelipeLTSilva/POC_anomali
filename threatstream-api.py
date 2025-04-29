import requests

# ==== CONFIGURAÇÕES ====
USERNAME = 'gpereira1@lenovo.com'
API_KEY = '9ad6b305eb3b5787751936e74b54e6c67b99a6b0'
BASE_URL = 'https://api.threatstream.com/api/v1/threat_model_search/'

# ==== CABEÇALHOS DE AUTENTICAÇÃO ====
HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}


def buscar_threat_models(limit=10, offset=0):
    """
    Consulta o endpoint threat_model_search da API da Anomali.
    
    :param limit: Quantidade de resultados a retornar.
    :param offset: Ponto de partida para paginação.
    :return: Lista de objetos retornados pela API.
    """
    params = {
        'limit': limit,
        'offset': offset
    }

    try:
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()  # Gera exceção automática se for 4xx ou 5xx

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


# ==== EXECUÇÃO ====
if __name__ == '__main__':
    buscar_threat_models(limit=5)
