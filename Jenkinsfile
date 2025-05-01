pipeline {
    agent any

    environment {
        // Defina o caminho do arquivo de timestamp
        TIMESTAMP_FILE = 'last_timestamp.txt'
    }

    stages {
        stage('Read Last Timestamp') {
            steps {
                script {
                    // Verifica se o arquivo last_timestamp.txt existe
                    if (fileExists(TIMESTAMP_FILE)) {
                        // Se o arquivo existe, lê o último timestamp
                        env.LAST_TIMESTAMP = readFile(TIMESTAMP_FILE).trim()
                        echo "Último timestamp encontrado: ${env.LAST_TIMESTAMP}"
                    } else {
                        // Se o arquivo não existe (primeira execução), define um timestamp inicial
                        env.LAST_TIMESTAMP = '20250401T000000'  // Exemplo de valor para a primeira execução
                        echo "Arquivo não encontrado, usando o timestamp inicial: ${env.LAST_TIMESTAMP}"
                    }
                }
            }
        }

        stage('Run API Test') {
            steps {
                // Utiliza as credenciais de forma segura para passar para o script Python
                withCredentials([usernamePassword(credentialsId: 'anomali-creds',
                                                 usernameVariable: 'ANOMALI_CREDS_USR',
                                                 passwordVariable: 'ANOMALI_CREDS_PSW')]) {
                    script {
                        // Passa o timestamp como argumento para o script Python
                        sh """
                            python3 threatstream-api.py threat_model_search \\
                            "$ANOMALI_CREDS_USR" "$ANOMALI_CREDS_PSW" "$LAST_TIMESTAMP"
                        """
                    }
                }
            }
        }

        stage('Update Timestamp') {
            steps {
                script {
                    // Após a execução do script Python, definimos o novo timestamp
                    // Vamos supor que o script retorna o novo timestamp ou você pode usar a data atual

                    // Aqui, definimos o timestamp para agora, mas idealmente você deve obter isso do script Python.
                    def newTimestamp = new Date().format('yyyyMMdd\'T\'HHmmss')

                    // Atualiza o arquivo last_timestamp.txt com o novo timestamp
                    writeFile file: TIMESTAMP_FILE, text: newTimestamp
                    echo "Novo timestamp gravado: ${newTimestamp}"
                }
            }
        }
    }

    post {
        success {
            echo "Pipeline executado com sucesso!"
        }
        failure {
            echo "Pipeline falhou!"
        }
    }
}
