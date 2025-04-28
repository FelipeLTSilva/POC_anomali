pipeline {
    agent any

    environment {
        ANOMALI_CREDS = credentials('anomali-creds') // ID da credencial
    }

    stages {
        stage('Run API Test') {
            steps {
                script {
                    def consulta = "intelligence"
                    // sh "python3 threatstream-api.py ${consulta} ${env.ANOMALI_CREDS_USR} ${env.ANOMALI_CREDS_PSW}"
                    sh '/usr/bin/python3 threatstream-api.py intelligence "$ANOMALI_CREDS_USR" "$ANOMALI_CREDS_PSW"'
                }
            }
        }
    }
}
