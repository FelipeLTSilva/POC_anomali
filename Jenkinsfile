pipeline {
    agent any
    environment {
        TS_USERNAME = credentials('gpereira1@lenovo.com')
        TS_APIKEY = credentials('9ad6b305eb3b5787751936e74b54e6c67b99a6b0')
    }
    stages {
        stage('Run API Test') {
            steps {
                script {
                    def consulta = "intelligence"  // Substitua com a consulta que deseja realizar
                    sh "python3 threatstreap-api.py ${consulta} ${TS_USERNAME} ${TS_APIKEY}"
                }
            }
        }
    }
}
