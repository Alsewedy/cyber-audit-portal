pipeline {
    agent any

    environment {
        IMAGE = 'ghcr.io/alsewedy/cyber-audit-portal'
        TAG = "build-${BUILD_NUMBER}"
        WEB01 = 'alsewedy@192.168.20.40'
        APP_DIR = '/opt/cyber-audit-portal'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Image') {
            steps {
                sh '''
                    docker build \
                      -t $IMAGE:latest \
                      -t $IMAGE:$TAG \
                      .
                '''
            }
        }

        stage('Push Image') {
            steps {
                withCredentials([string(credentialsId: 'ghcr-token', variable: 'GHCR_TOKEN')]) {
                    sh '''
                        echo "$GHCR_TOKEN" | docker login ghcr.io -u Alsewedy --password-stdin
                        docker push $IMAGE:latest
                        docker push $IMAGE:$TAG
                    '''
                }
            }
        }

        stage('Deploy to WEB01') {
            steps {
                sshagent(credentials: ['web01-ssh-key']) {
                    sh '''
                        ssh -o StrictHostKeyChecking=no $WEB01 "
                          cd $APP_DIR &&
                          docker compose pull &&
                          docker compose up -d &&
                          docker image prune -f &&
                          docker ps
                        "
                    '''
                }
            }
        }
    }
}
