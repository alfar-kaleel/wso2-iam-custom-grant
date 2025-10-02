pipeline {
    agent any

    environment {
        MAVEN_HOME = tool 'Maven'  // Use the configured Maven tool
        NEXUS_URL = 'http://localhost:8081'  // Correct Nexus base URL
        NEXUS_CREDENTIALS = 'nexus-credentials' // Jenkins stored credentials ID for Nexus
    }

   stage('Checkout the branch') {
            steps {
                git branch: 'develop', url: 'https://github.com/alfar-kaleel/wso2-iam-custom-grant.git'
            }
        }

        stage('Build jar file') {
            steps {
                sh "${MAVEN_HOME}/bin/mvn clean install"
            }
        }

        stage('Upload to Nexus') {
            steps {
                nexusArtifactUploader(
                    nexusVersion: 'nexus3',
                    protocol: 'http',
                    nexusUrl: "localhost:8081",  // Correct Nexus base URL
                    repository: 'maven-releases',
                    groupId: 'com.example.customgrant.apis',
                    version: "1.0.0${BUILD_NUMBER}",
                    credentialsId: "${NEXUS_CREDENTIALS}",
                    artifacts: [[
                        artifactId: 'custom-grant',
                        classifier: '',
                        type: 'jar',
                        file: 'target/custom-grant_1.0.0.car'
                    ]]
                )
            }
        }
    }
}
