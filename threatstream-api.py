import requests
import sys
import re
import json
from datetime import datetime
import os

# ==== INITIAL CONFIGURATION ==== 
# Script expects 3 arguments: <endpoint> <username> <apikey>
# timestamp is optional: if not provided, we will attempt to read it from 'last_timestamp.txt'
if len(sys.argv) < 4 or len(sys.argv) > 5:
    print("Correct usage: python3 threatstream-api.py <endpoint> <username> <apikey> [timestamp]")
    sys.exit(1)

ENDPOINT = sys.argv[1]
USERNAME = sys.argv[2]
API_KEY = sys.argv[3]
TIMESTAMP = sys.argv[4] if len(sys.argv) == 5 else None

BASE_URL = 'https://api.threatstream.com/api/v1'
HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# ==== KEYWORDS TO MATCH IN NAME FIELD ====
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud']
INTEL_MODELS = {'tipreport', 'ttp', 'tool', 'campaign', 'actor', 'vulnerability', 'incident'}

# === Helper function to match any keyword ===
def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

# === Helper function to read timestamp from last_timestamp.txt ===
def get_last_timestamp():
    if os.path.exists('last_timestamp.txt'):
        with open('last_timestamp.txt', 'r') as f:
            return f.read().strip()
    else:
        return None

# === Main function to retrieve data from ThreatStream ===
def buscar_threat_models(endpoint, timestamp, limit=1000, offset=0):
    """
    Query the given ThreatStream endpoint and return filtered results.
    """
    resultados = []

    while True:
        params = {'limit': limit, 'offset': offset}
        if timestamp:
            params['modified_ts__gte'] = timestamp  # Use timestamp filter if provided

        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()

        data = response.json()
        objetos = data.get('objects', [])
        if not objetos:
            break

        for obj in objetos:
            name = obj.get('name', '')
            modified_ts = obj.get('modified_ts', '')

            # Step 1.2: Filter based on name keyword match
            if name and keyword_match(name):
                model_id = obj.get('id')
                model_type = obj.get('model_type', endpoint)  # fallback to endpoint name

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

                # Step 3: If model_type supports observables, fetch them
                if model_type in INTEL_MODELS:
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
        # If no timestamp is passed, get it from the file
        if not TIMESTAMP:
            TIMESTAMP = get_last_timestamp()  # Read from last_timestamp.txt if no argument

        # If no timestamp is available (both passed and from file), use a default or exit
        if not TIMESTAMP:
            print("No timestamp found. Please provide a valid timestamp or ensure last_timestamp.txt is available.")
            sys.exit(1)

        # Fetch and process results
        resultados = buscar_threat_models(ENDPOINT, TIMESTAMP, limit=1000)

        # Step 4: Print final JSON
        print(json.dumps(resultados, indent=2, ensure_ascii=False))

        # Optionally: You can update last_timestamp.txt with the latest timestamp after processing

    except requests.exceptions.RequestException as e:
        print(f"Connection or HTTP error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
