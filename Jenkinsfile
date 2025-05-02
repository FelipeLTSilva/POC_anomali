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
                        env.LAST_TIMESTAMP = '20250101T000000'  // valor padrão
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

        stage('Commit Timestamp') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'github-token',
                                                  usernameVariable: 'GIT_USER',
                                                  passwordVariable: 'GIT_TOKEN')]) {
                    sh '''
                        git config user.email "jenkins@yourdomain.com"
                        git config user.name "Jenkins CI"
                        git add last_timestamp.txt
                        git commit -m "Update timestamp [skip ci]" || echo "No changes to commit"
                        git push https://${GIT_USER}:${GIT_TOKEN}@github.com/FelipeLTSilva/POC_anomali.git HEAD:main
                    '''
                }
            }
        }
    }

    post {
        failure {
            echo "🚨 Pipeline falhou!"
        }
    }
}
