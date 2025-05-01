pipeline {
    agent any

    environment {
        ANOMALI_CREDS = credentials('anomali-creds')         // API credentials
        GIT_CREDS = credentials('github-push-token')         // GitHub token credentials
        TIMESTAMP_FILE = 'last_timestamp.txt'
    }

    stages {
        stage('Checkout') {
            steps {
                // Clona o repositório com permissão de push
                git credentialsId: 'github-push-token', url: 'https://github.com/seu-usuario/seu-repo.git', branch: 'main'
            }
        }

        stage('Read Last Timestamp') {
            steps {
                script {
                    if (fileExists(env.TIMESTAMP_FILE)) {
                        env.LAST_TS = readFile(env.TIMESTAMP_FILE).trim()
                        echo "🔁 Último timestamp coletado: ${env.LAST_TS}"
                    } else {
                        env.LAST_TS = '20000101T000000'
                        echo "⚠️ Arquivo de timestamp não encontrado. Usando valor padrão: ${env.LAST_TS}"
                    }
                }
            }
        }

        stage('Run Script') {
            steps {
                script {
                    sh """
                        python3 threatstream-api.py threat_model_search \
                        "${ANOMALI_CREDS_USR}" "${ANOMALI_CREDS_PSW}" \
                        --since "${env.LAST_TS}"
                    """
                }
            }
        }

        stage('Update Timestamp') {
            steps {
                script {
                    def newTs = new Date().format("yyyyMMdd'T'HHmmss", TimeZone.getTimeZone('UTC'))
                    writeFile file: env.TIMESTAMP_FILE, text: newTs
                    sh """
                        git config user.name "Jenkins Bot"
                        git config user.email "jenkins@bot.com"
                        git add ${env.TIMESTAMP_FILE}
                        git commit -m "Atualiza timestamp para ${newTs}" || echo "Nada para commitar"
                        git push https://${GIT_CREDS_USR}:${GIT_CREDS_PSW}@github.com/seu-usuario/seu-repo.git HEAD:main
                    """
                }
            }
        }
    }
}
