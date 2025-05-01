pipeline {
    agent any

    environment {
        LAST_TIMESTAMP_FILE = 'last_timestamp.txt'
    }

    stages {
        stage('Read Last Timestamp') {
            steps {
                script {
                    if (fileExists(env.LAST_TIMESTAMP_FILE)) {
                        env.LAST_TIMESTAMP = readFile(env.LAST_TIMESTAMP_FILE).trim()
                    } else {
                        env.LAST_TIMESTAMP = '20250101T000000'  // Valor inicial padrão
                    }
                    echo "🔁 Último timestamp coletado: ${env.LAST_TIMESTAMP}"
                }
            }
        }

        stage('Run Script') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'anomali-creds',
                                                  usernameVariable: 'ANOMALI_CREDS_USR',
                                                  passwordVariable: 'ANOMALI_CREDS_PSW')]) {
                    sh '''
                        python3 threatstream-api.py threat_model_search "$ANOMALI_CREDS_USR" "$ANOMALI_CREDS_PSW" "$LAST_TIMESTAMP"
                    '''
                }
            }
        }

        stage('Update Timestamp') {
            steps {
                script {
                    def newTimestamp = new Date().format("yyyyMMdd'T'HHmmss")
                    writeFile file: env.LAST_TIMESTAMP_FILE, text: newTimestamp
                    echo "🕒 Novo timestamp gravado: ${newTimestamp}"
                }
            }
        }
    }

    post {
        failure {
            echo "Pipeline falhou!"
        }
    }
}
