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
                    echo "User: ${ANOMALI_CREDS_USR}"  // Debug: verificar o usuário
                    echo "Password: ${ANOMALI_CREDS_PSW}"  // Debug: verificar a senha
                    sh "python3 threatstream-api.py intelligence '$ANOMALI_CREDS_USR' '$ANOMALI_CREDS_PSW'"
                }
            }
        }
    }
}
