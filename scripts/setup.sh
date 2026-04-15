#!/bin/bash
set -euo pipefail

# Installe les dependencies necessary
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Initialise le projet
docker-compose up -d