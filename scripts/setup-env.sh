#!/bin/bash
set -euo pipefail

# Installation des dependencies
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Configuration de Docker
sudo systemctl start docker
sudo systemctl enable docker

# Creation du directory de data
mkdir -p data