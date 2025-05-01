pipeline {
    agent any

    environment {
        // Referência à credencial ANOMALI_CREDS
        ANOMALI_CREDS = credentials('ANOMALI_CREDS')  // Nome correto da credencial
    }

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/FelipeLTSilva/POC_anomali.git'  // Seu repositório no GitHub
            }
        }

        stage('Read Last Timestamp') {
            steps {
                script {
                    // Lê o último timestamp do arquivo last_timestamp.txt
                    def lastTimestamp = readFile('last_timestamp.txt').trim()
                    echo "🔁 Último timestamp coletado: ${lastTimestamp}"

                    // Armazena o timestamp em uma variável de ambiente
                    env.LAST_TIMESTAMP = lastTimestamp
                }
            }
        }

        stage('Run Script') {
            steps {
                script {
                    // Passa o timestamp como argumento para o script Python e usa a credencial
                    sh """
                        python3 threatstream-api.py threat_model_search ${ANOMALI_CREDS_USR} ${ANOMALI_CREDS_PSW} ${env.LAST_TIMESTAMP}
                    """
                }
            }
        }

        stage('Update Timestamp') {
            steps {
                script {
                    // Atualiza o arquivo last_timestamp.txt com o novo timestamp
                    def newTimestamp = "20250501T000000"  // Exemplo, você precisará capturar o novo timestamp da resposta da API
                    writeFile file: 'last_timestamp.txt', text: newTimestamp
                    echo "Novo timestamp gravado: ${newTimestamp}"
                }
            }
        }
    }
}
