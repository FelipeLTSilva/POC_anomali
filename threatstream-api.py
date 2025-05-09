import requests
import sys
import json
from datetime import datetime

# ==== KEYWORDS TO FILTER ==== 
KEYWORDS = ['aws', 'azure', 'kubernetes', 'k8s', 'vulnerability', 'incident', 'cloud']

# ==== SUPPORTED MODELS ====
INTEL_MODELS = {'tipreport', 'ttp', 'tool', 'campaign', 'actor', 'vulnerability', 'incident'}

# ==== Helper Functions ====

def keyword_match(text):
    """Check if any keyword matches the provided text"""
    return any(kw.lower() in text.lower() for kw in KEYWORDS)

def format_timestamp_for_api(ts):
    """Format timestamp for API request"""
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        print("❌ Invalid timestamp. Please use the format: YYYYMMDDTHHMMSS")
        sys.exit(1)

def detalhar_modelo(model_type, model_id, resultado):
    """Fetch additional details for the given model, e.g., tags"""
    url = f'{BASE_URL}/{model_type}/{model_id}/'
    response = requests.get(url, headers=HEADERS)
    if response.ok:
        obj = response.json()
        # Ensure that tags are not empty
        resultado['tags'] = obj.get('tags', [])
        # Additional fields can be fetched and checked here as needed
        if not resultado['tags']:
            resultado['tags'] = ["No tags available"]  # Default if tags are missing

def buscar_observables(model_type, model_id, resultado):
    """Fetch observables related to the given model"""
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
        if not resultado['observables']:
            resultado['observables'] = ["No observables found"]  # Default if observables are missing

def buscar_threat_models(endpoint, timestamp=None, limit=500, offset=0):
    """Search for threat models and filter based on keywords"""
    resultados = []

    while True:
        params = {'limit': limit, 'offset': offset}
        if timestamp:
            params['created_ts__gte'] = timestamp

        response = requests.get(f'{BASE_URL}/{endpoint}/', headers=HEADERS, params=params)
        response.raise_for_status()

        objetos = response.json().get('objects', [])
        if not objetos:
            break

        for obj in objetos:
            name = obj.get('name', '')
            created_ts = obj.get('created_ts', '')
            model_id = obj.get('id')
            model_type = obj.get('model_type', endpoint)

            if name and keyword_match(name) and model_type in INTEL_MODELS:
                resultado = {
                    'id': model_id,
                    'model_type': model_type,
                    'name': name,
                    'created_ts': created_ts,
                    'link': f'https://ui.threatstream.com/{model_type}/{model_id}',
                    'tags': [],
                    'observables': []
                }

                # Fetch model details and observables
                detalhar_modelo(model_type, model_id, resultado)
                buscar_observables(model_type, model_id, resultado)
                resultados.append(resultado)

        if not response.json().get('next'):
            break
        offset += limit

    return resultados

# ==== Integration with Halo ITSM ====

def obter_token_halo(client_id, client_secret):
    """Obtain an authentication token from Halo ITSM"""
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
    """Create a new ticket in Halo ITSM"""
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
            {"id": 260, "value": resultado['created_ts']},
            {"id": 257, "value": resultado['link']},
            {"id": 258, "value": ", ".join(resultado['tags'])},
            {"id": 259, "value": json.dumps(resultado['observables'])}
        ]
    }]

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        print(f"✅ Ticket created: {resultado['name']} (ID: {resultado['id']})")
    else:
        print(f"❌ Failed to create ticket ({resultado['id']}): {response.status_code} - {response.text}")

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
        # Get results from threat model search
        resultados = buscar_threat_models(ENDPOINT, timestamp=TIMESTAMP)
        print(f"🔎 {len(resultados)} items found")

        if resultados:
            token = obter_token_halo(HALO_CLIENT_ID, HALO_CLIENT_SECRET)
            for r in resultados:
                # Only send results with non-empty required fields
                if r.get('name') and r.get('created_ts') and r.get('tags') and r.get('observables'):
                    criar_ticket_halo(token, r)
                else:
                    print(f"⚠️ Ignored result (missing data): ID {r.get('id')}")
        else:
            print("ℹ️ No results matching the criteria.")

    except Exception as e:
        print(f"❗Error: {e}")
