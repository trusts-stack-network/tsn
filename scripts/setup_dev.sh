#!/bin/bash
set -euo pipefail

# Installer les dependencies
sudo apt update
sudo apt install -y docker.io git

# Configurer Docker
sudo systemctl start docker
sudo systemctl enable docker

# Cloner le deposit Git
git clone https://github.com/mytsn/tsn.git
cd tsn

# Construire l'image Docker
docker build -t mytsn .

# Execute le conteneur
docker run -p 8080:8080 mytsn