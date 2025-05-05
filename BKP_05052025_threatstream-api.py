import requests
import sys
import json
from datetime import datetime

# ==== KEYWORDS TO MATCH IN NAME FIELD ====
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud']

# ==== MODEL TYPES TO SEARCH FOR OBSERVABLES ====
INTEL_MODELS = {'tipreport', 'ttp', 'tool', 'campaign', 'actor', 'vulnerability', 'incident'}

# ==== Helper: Check if name matches any keyword ====
def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

# ==== Helper: Format timestamp for API ====
def format_timestamp_for_api(ts):
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        print("❌ Timestamp format is invalid. Expected format: YYYYMMDDTHHMMSS")
        sys.exit(1)

# ==== Get model details (tags) ====
def detalhar_modelo(model_type, model_id, resultado):
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        resultado['tags'] = obj.get('tags', [])

# ==== Get observables if supported ====
def buscar_observables(model_type, model_id, resultado):
    url = f'{BASE_URL}/{model_type}/{model_id}/intelligence/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        data = response.json()
        observables = []
        for item in data.get('objects', []):
            value = item.get('value')
            itype = item.get('itype')
            if value and itype:
                observables.append({'value': value, 'itype': itype})
        resultado['observables'] = observables

# ==== Main query function ====
def buscar_threat_models(endpoint, timestamp=None, limit=2, offset=0):
    resultados = []

    while True:
        params = {'limit': limit, 'offset': offset}
        if timestamp:
            params['modified_ts__gte'] = timestamp

        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()

        data = response.json()
        objetos = data.get('objects', [])
        if not objetos:
            break

        for obj in objetos:
            name = obj.get('name', '')
            modified_ts = obj.get('modified_ts', '')
            model_id = obj.get('id')
            model_type = obj.get('model_type', endpoint)

            if name and keyword_match(name) and model_type in INTEL_MODELS:
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

        if not data.get('next'):
            break
        offset += limit

    return resultados

# ==== Entry Point ====
if __name__ == '__main__':
    if len(sys.argv) not in [4, 5]:
        print("Usage: python3 threatstream-api.py <endpoint> <username> <apikey> [timestamp]")
        sys.exit(1)

    ENDPOINT = sys.argv[1]
    USERNAME = sys.argv[2]
    API_KEY = sys.argv[3]
    LAST_TIMESTAMP = format_timestamp_for_api(sys.argv[4]) if len(sys.argv) == 5 else None

    BASE_URL = 'https://api.threatstream.com/api/v1'
    HEADERS = {
        'Authorization': f'apikey {USERNAME}:{API_KEY}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    try:
        resultados = buscar_threat_models(ENDPOINT, timestamp=LAST_TIMESTAMP)
        print(json.dumps(resultados, indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(f"Connection or HTTP error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
