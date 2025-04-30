import requests
import sys
import time

# Step 1: Validating arguments from the command line (Endpoint, Username, and API Key)
if len(sys.argv) != 4:
    print("Usage: python3 threatstream-api.py <endpoint> <username> <apikey>")
    sys.exit(1)

ENDPOINT = sys.argv[1]    # The API endpoint, e.g., "tipreport", "actor", etc.
USERNAME = sys.argv[2]    # Your username for Anomali ThreatStream
API_KEY = sys.argv[3]     # Your API key for Anomali ThreatStream

# Step 2: Define base URL and headers for authentication
BASE_URL = f'https://api.threatstream.com/api/v1/{ENDPOINT}/'

HEADERS = {
    'Authorization': f'apikey {USERNAME}:{API_KEY}',  # Basic authentication using API key
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Optional: Filter for a specific ID. Uncomment to use.
# You can manually specify an ID to only get that result.
FILTER_ID = 1509526  # Set this to a specific ID (e.g., 24398393) or leave as None to get all results.

# Function to search for threat models or entities
def buscar(limit=5, offset=0):
    params = {'limit': limit, 'offset': offset}  # Pagination parameters

    try:
        # Step 3: Make a GET request to the ThreatStream API
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        dados = response.json()  # Convert response to JSON
        
        # Step 4: Extract the list of objects
        objetos = dados.get('objects', [])
        
        if not objetos:
            print("No results found.")
        else:
            print(f"✅ Found {len(objetos)} results:")
            
            # Step 5: Loop through the results to display ID, name, and model type
            for obj in objetos:
                obj_id = obj.get('id')
                
                # Step 6: Filter based on the specified FILTER_ID if provided
                if FILTER_ID and obj_id != FILTER_ID:
                    continue  # Skip objects that don't match the FILTER_ID

                obj_name = obj.get('name', 'No name provided')
                obj_type = obj.get('model_type', 'Unknown type')

                print(f"- ID: {obj_id} | Name: {obj_name} | Type: {obj_type}")
                
                # Step 7: Build a URL to the ThreatStream UI for this entity
                url = f"https://ui.threatstream.com/{obj_type}/{obj_id}"
                print(f"Link: {url}")
                
                # Step 8: Access additional details for the object
                url_intelligence = f"{BASE_URL}{obj_id}/intelligence/"
                intelligence_response = requests.get(url_intelligence, headers=HEADERS)
                
                # If successful, parse the intelligence data
                if intelligence_response.status_code == 200:
                    intelligence_data = intelligence_response.json()
                    observables = intelligence_data.get('observables', [])
                    for observable in observables:
                        value = observable.get('value')
                        itype = observable.get('itype')
                        print(f"Observable: Value: {value}, Type: {itype}")

                else:
                    print(f"Failed to get intelligence data for {obj_name}")

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error: {http_err} - {response.text}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == '__main__':
    buscar()
