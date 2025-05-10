import requests
import sys
import json
from datetime import datetime

# ==== KEYWORDS FOR FILTERING ====
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud']

# ==== SUPPORTED INTEL MODELS ====
INTEL_MODELS = {'tipreport', 'ttp', 'tool', 'campaign', 'actor', 'vulnerability', 'incident'}

# ==== Utility Functions ====

def keyword_match(text):
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

def format_timestamp_for_api(ts):
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # Added 'Z' for UTC
    except ValueError:
        print("❌ Invalid timestamp. Use: YYYYMMDDTHHMMSS")
        sys.exit(1)

def get_model_details(model_type, model_id, result):
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        result['tags'] = obj.get('tags', [])

def fetch_observables(model_type, model_id, result):
    url = f'{BASE_URL}/{model_type}/{model_id}/intelligence/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        observables = []
        for item in response.json().get('objects', []):
            value = item.get('value')
            itype = item.get('itype')
            if value and itype:
                observables.append({'value': value, 'itype': itype})
        result['observables'] = observables

def fetch_threat_models(endpoint, timestamp=None, limit=100, offset=0):
    results = []

    while True:
        params = {'limit': limit, 'offset': offset}
        if timestamp:
            params['created_ts__gte'] = timestamp

        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()

        objects = response.json().get('objects', [])
        if not objects:
            break

        for obj in objects:
            name = obj.get('name', '')
            created_ts = obj.get('created_ts', '')
            model_id = obj.get('id')
            model_type = obj.get('model_type', endpoint)

            if name and keyword_match(name) and model_type in INTEL_MODELS:
                result = {
                    'id': model_id,
                    'model_type': model_type,
                    'name': name,
                    'created_ts': created_ts,
                    'link': f'https://ui.threatstream.com/{model_type}/{model_id}',
                    'tags': [],
                    'observables': []
                }

                get_model_details(model_type, model_id, result)
                fetch_observables(model_type, model_id, result)
                results.append(result)

        if not response.json().get('next'):
            break
        offset += limit

    return results

# ==== HALO ITSM Integration ====

def get_halo_token(client_id, client_secret):
    url = "https://scoesoc.haloitsm.com/auth/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def create_halo_ticket(token, result):
    url = "https://scoesoc.haloitsm.com/api/tickets"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = [{
        "summary": f"[Threatstream] {result['model_type']} {result['id']}",
        "details": f"Link: {result['link']}",
        "tickettype_id": 42,
        "team": "SMEs",
        "priority_id": 1,
        "customfields": [
            {"name": "CFThreatstreamid", "value": str(result['id'])},
            {"name": "CFThreatstreammodeltype", "value": result['model_type']},
            {"name": "CFThreatstreamname", "value": result['name']},
            {"name": "CFThreatstreamcreatedts", "value": result['created_ts']},
            {"name": "CFThreatstreamlink", "value": result['link']},
            {"name": "CFThreatstreamtags", "value": json.dumps(result['tags'])},
            {"name": "CFThreatstreamobservables", "value": json.dumps(result['observables'])}
        ]
    }]

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        print(f"✅ Ticket created: {result['name']} (ID: {result['id']})")
    else:
        print(f"❌ Failed to create ticket ({result['id']}): {response.status_code} - {response.text}")

# ==== Entry Point ====

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print("Usage: python3 threatstream-api.py <endpoint> <anomali_user> <anomali_apikey> <timestamp> <halo_client_id> <halo_client_secret>")
        sys.exit(1)

    ENDPOINT = sys.argv[1]
    USERNAME = sys.argv[2]
    API_KEY = sys.argv[3]
    TIMESTAMP = format_timestamp_for_api(sys.argv[4])
    HALO_CLIENT_ID = sys.argv[5]
    HALO_CLIENT_SECRET = sys.argv[6]

    BASE_URL = 'https://api.threatstream.com/api/v1'
    HEADERS = {
        'Authorization': f'apikey {USERNAME}:{API_KEY}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    try:
        results = fetch_threat_models(ENDPOINT, timestamp=TIMESTAMP)
        print(f"🔎 {len(results)} items found")

        if results:
            token = get_halo_token(HALO_CLIENT_ID, HALO_CLIENT_SECRET)
            for r in results:
                create_halo_ticket(token, r)
        else:
            print("ℹ️ No results found with the given criteria.")

    except Exception as e:
        print(f"❗Error: {e}")
