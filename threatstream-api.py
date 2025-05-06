import requests
import sys
import json
from datetime import datetime
import os

# ==== CONFIGURAÇÕES ====
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud']
INTEL_MODELS = {'tipreport', 'ttp', 'tool', 'campaign', 'actor', 'vulnerability', 'incident'}
LAST_TIMESTAMP_FILE = 'last_timestamp.txt'

# ==== Funções Auxiliares ====

def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

def format_timestamp_for_api(ts):
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        print("❌ Timestamp inválido. Use: YYYYMMDDTHHMMSS")
        sys.exit(1)

def read_last_timestamp():
    if os.path.exists(LAST_TIMESTAMP_FILE):
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            return f.read().strip()
    return None

def write_last_timestamp(ts):
    with open(LAST_TIMESTAMP_FILE, 'w') as f:
        f.write(ts)

def detalhar_modelo(model_type, model_id, resultado):
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        resultado['tags'] = obj.get('tags', [])

def buscar_observables(model_type, model_id, resultado):
    url = f'{BASE_URL}/{model_type}/{model_id}/intelligence/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        observables = []
        for item in response.json().get('objects', []):
            value = item.get('value')
            itype = item.get('itype')
            if value and itype:
                observables.append({'value': value, 'itype': itype})
        resultado['observables'] = observables

def buscar_por_modelo(model_type, timestamp, limit=3):
    offset = 0
    resultados = []

    while True:
        params = {'limit': limit, 'offset': offset, 'ordering': '-modified_ts'}
        if timestamp:
            params['modified_ts__gte'] = timestamp

        url = f'{BASE_URL}/{model_type}/'
        response = requests.get(url, headers=HEADERS, params=params)
        response.raise_for_status()

        objetos = response.json().get('objects', [])
        if not objetos:
            break

        for obj in objetos:
            name = obj.get('name', '')
            modified_ts = obj.get('modified_ts', '')
            model_id = obj.get('id')

            if name and keyword_match(name):
                resultado = {
                    'id': model_id,
                    'model_type': model_type,
                    'name': name,
                    'modified_ts': modified_ts,
                    'link': f'https://ui.threatstream.com/{model_type}/{model_id}',
                    'tags': [],
                    'observables': []
                }
                detalhar_modelo(model_type, model_id, resultado)
                buscar_observables(model_type, model_id, resultado)
                resultados.append(resultado)

        if not response.json().get('next'):
            break
        offset += limit

    return resultados

def buscar_todos_modelos(timestamp):
    todos_resultados = []
    for model in INTEL_MODELS:
        print(f"🔎 Buscando modelo: {model}")
        resultados = buscar_por_modelo(model, timestamp)
        todos_resultados.extend(resultados)
    return todos_resultados

# ==== Integração com Halo ITSM ====

def obter_token_halo(client_id, client_secret):
    url = "https://scoesoc.haloitsm.com/auth/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def criar_ticket_halo(token, resultado):
    url = "https://scoesoc.haloitsm.com/api/tickets"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = [{
        "summary": f"[Threatstream] {resultado['model_type']} {resultado['id']}",
        "details": f"Link: {resultado['link']}",
        "tickettype_id": 42,
        "team": "SMEs",
        "priority_id": 1,
        "customfields": [
            {"id": 253, "value": str(resultado['id'])},
            {"id": 254, "value": resultado['model_type']},
            {"id": 255, "value": resultado['name']},
            {"id": 256, "value": resultado['modified_ts']},
            {"id": 257, "value": resultado['link']},
            {"id": 258, "value": ", ".join(resultado['tags'])},
            {"id": 259, "value": json.dumps(resultado['observables'])}
        ]
    }]

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        print(f"✅ Ticket criado: {resultado['name']} (ID: {resultado['id']})")
    else:
        print(f"❌ Falha ao criar ticket ({resultado['id']}): {response.status_code} - {response.text}")

# ==== Entry Point ====

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("Uso: python3 threatstream-api.py <anomali_user> <anomali_apikey> <halo_client_id> <halo_client_secret> <timestamp-opcional>")
        sys.exit(1)

    USERNAME = sys.argv[1]
    API_KEY = sys.argv[2]
    HALO_CLIENT_ID = sys.argv[3]
    HALO_CLIENT_SECRET = sys.argv[4]
    CLI_TIMESTAMP = sys.argv[5] if len(sys.argv) == 6 else None

    BASE_URL = 'https://api.threatstream.com/api/v1'
    HEADERS = {
        'Authorization': f'apikey {USERNAME}:{API_KEY}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    timestamp = format_timestamp_for_api(CLI_TIMESTAMP) if CLI_TIMESTAMP else read_last_timestamp()

    try:
        resultados = buscar_todos_modelos(timestamp)
        print(f"🔍 {len(resultados)} resultados com palavras-chave encontradas.")

        if resultados:
            token = obter_token_halo(HALO_CLIENT_ID, HALO_CLIENT_SECRET)
            for r in resultados:
                criar_ticket_halo(token, r)

            # Atualiza o timestamp para o mais recente encontrado
            mais_recente = max(r['modified_ts'] for r in resultados)
            write_last_timestamp(mais_recente)
        else:
            print("ℹ️ Nenhum resultado com os critérios definidos.")

    except Exception as e:
        print(f"❗Erro: {e}")
