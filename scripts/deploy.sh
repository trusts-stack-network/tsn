#!/bin/bash
set -euo pipefail

# Deploy l'image Docker sur un server distant
ssh user@host "docker pull ${{ secrets.DOCKER_USERNAME }}/tsn:latest"
ssh user@host "docker run -d -p 8080:8080 ${{ secrets.DOCKER_USERNAME }}/tsn:latest"