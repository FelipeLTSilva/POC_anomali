pipeline {
    agent any

    stages {
        stage('Run API Test') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'anomali-creds',
                                                 usernameVariable: 'ANOMALI_CREDS_USR',
                                                 passwordVariable: 'ANOMALI_CREDS_PSW')]) {
                    sh '''
                        python3 threatstream-api.py intelligence "$ANOMALI_CREDS_USR" "$ANOMALI_CREDS_PSW"
                    '''
                }
            }
        }
    }
}
