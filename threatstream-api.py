import sys
import requests
from datetime import datetime

def threat_model_search(username, api_key, timestamp=None):
    # Verifique se o timestamp foi passado
    if timestamp:
        print(f"Buscando dados a partir do timestamp: {timestamp}")
    else:
        print("Nenhum timestamp fornecido, usando o valor padrão.")
    
    # Simula consulta na API com base no timestamp (isso deve ser implementado conforme a lógica da API)
    # Exemplo de URL da API, substitua pela URL real da API que você está utilizando.
    api_url = f'https://api.example.com/threats?since={timestamp}'  # Exemplo de URL
    response = requests.get(api_url, auth=(username, api_key))
    
    if response.status_code == 200:
        print("Consulta realizada com sucesso!")
        # Aqui você pode processar a resposta e, se necessário, retornar um novo timestamp
        # Vamos supor que você obtenha o novo timestamp a partir da resposta
        # Exemplo: novo_timestamp = response.json().get("last_updated")
        novo_timestamp = datetime.now().strftime('%Y%m%dT%H%M%S')  # Exemplo de novo timestamp
        print(f"Novo timestamp: {novo_timestamp}")
        
        return novo_timestamp  # Retorna o novo timestamp (ou qualquer outra lógica que você precise)
    else:
        print(f"Erro na consulta da API: {response.status_code}")
        return None

if __name__ == "__main__":
    # Recebe os parâmetros do Jenkins
    if len(sys.argv) > 1:
        username = sys.argv[1]
        api_key = sys.argv[2]
        timestamp = sys.argv[3] if len(sys.argv) > 3 else None
        
        novo_timestamp = threat_model_search(username, api_key, timestamp)
        if novo_timestamp:
            print(novo_timestamp)  # Retorna o novo timestamp para o Jenkins gravar no arquivo
        else:
            print("Falha ao obter o novo timestamp.")
    else:
        print("Parâmetros insuficientes.")
