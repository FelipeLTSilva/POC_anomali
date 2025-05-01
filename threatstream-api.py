import requests
import sys
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

# ==== KEYWORDS TO MATCH IN NAME FIELD (case-insensitive) ====
# Loosely matching keywords for better hit rate
KEYWORDS = [
    'aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud',
    't1046', 't1055', 'network service scanning', 'process injection'
]

# ==== MODEL TYPES TO INCLUDE ====
# Limit processing only to these model types
INTEL_MODELS = {'ttp'}

# === Helper: Check if name contains any keyword ===
def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

# === Step 2.2: Retrieve detailed data for each object (e.g. tags) ===
def fetch_model_details(model_type, model_id, result):
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        result['tags'] = obj.get('tags', [])

# === Step 3.1: Retrieve intelligence observables for supported models ===
def fetch_observables(model_type, model_id, result):
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
        result['observables'] = observables

# === Main logic to fetch and filter threat models ===
def fetch_threat_models(endpoint, limit=1000, offset=0):
    results = []

    while True:
        params = {'limit': limit, 'offset': offset}
        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()

        data = response.json()
        objects = data.get('objects', [])
        if not objects:
            break

        for obj in objects:
            name = obj.get('name', '')
            model_id = obj.get('id')
            model_type = obj.get('model_type', endpoint).lower()
            modified_ts = obj.get('modified_ts', '')

            # === Skip if model_type is not in the allowed set ===
            if model_type not in INTEL_MODELS:
                continue

            # === Skip if name doesn't contain keywords ===
            if not keyword_match(name):
                continue

            # === Build base result object ===
            result = {
                'id': model_id,
                'model_type': model_type,
                'name': name,
                'modified_ts': modified_ts,
                'link': f'https://ui.threatstream.com/{model_type}/{model_id}',
                'tags': [],
                'observables': []
            }

            # === Add tags ===
            fetch_model_details(model_type, model_id, result)

            # === Add observables if model supports it ===
            if model_type in INTEL_MODELS:
                fetch_observables(model_type, model_id, result)

            results.append(result)

        # === Stop if there's no next page ===
        if not data.get('next'):
            break
        offset += limit

    return results

# === MAIN EXECUTION ===
if __name__ == '__main__':
    try:
        results = fetch_threat_models(ENDPOINT)
        print(json.dumps(results, indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(f"Connection or HTTP error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
