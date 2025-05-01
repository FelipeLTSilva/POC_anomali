import requests
import sys
import re
import json
from datetime import datetime

# ==== INITIAL CONFIGURATION ====
# Script expects 3 arguments: <endpoint> <username> <apikey>
if len(sys.argv) != 4:
    print("Correct usage: python3 threatstream-api.py <endpoint> <username> <apikey>")
    sys.exit(1)

ENDPOINT = sys.argv[1]
USERNAME = sys.argv[2]
API_KEY = sys.argv[3]

BASE_URL = 'https://api.threatstream.com/api/v1'
HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# ==== KEYWORDS TO MATCH IN NAME FIELD ====
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud', 't1046', 'process injection', 'network service scanning', 't1055']

# ==== MODEL TYPES TO SEARCH FOR OBSERVABLES ====
INTEL_MODELS = {'ttp'}

# === Helper function to match any keyword ===
def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

# === Main function to retrieve data from ThreatStream ===
def buscar_threat_models(endpoint, limit=1000, offset=0):
    """
    Query the given ThreatStream endpoint and return filtered results.
    """
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
            modified_ts = obj.get('modified_ts', '')
            model_id = obj.get('id')
            model_type = obj.get('model_type', endpoint)

            # ✅ Filter: only proceed if name matches and model_type is in list
            if name and keyword_match(name) and model_type in INTEL_MODELS:
                # Step 1.1 and 2: Collect core info + URL
                resultado = {
                    'id': model_id,
                    'model_type': model_type,
                    'name': name,
                    'modified_ts': modified_ts,
                    'link': f'https://ui.threatstream.com/{model_type}/{model_id}',
                    'tags': [],
                    'observables': []
                }

                # Step 2.2: Get extra details like tags
                detalhar_modelo(model_type, model_id, resultado)

                # Step 3: Get observables if model_type supports it
                buscar_observables(model_type, model_id, resultado)

                resultados.append(resultado)

        # Step 1.3: Pagination logic using 'next' from API
        if not data.get('next'):
            break
        offset += limit

    return resultados

# === Step 2.2: Retrieve detailed data for each object (e.g. tags) ===
def detalhar_modelo(model_type, model_id, resultado):
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        resultado['tags'] = obj.get('tags', [])

# === Step 3.1: Retrieve intelligence observables for supported models ===
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

# === MAIN EXECUTION BLOCK ===
if __name__ == '__main__':
    try:
        # Fetch and process results
        resultados = buscar_threat_models(ENDPOINT, limit=1000)

        # Step 4: Print final JSON
        print(json.dumps(resultados, indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(f"Connection or HTTP error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
