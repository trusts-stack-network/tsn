#!/bin/bash
set -euo pipefail

# Deploy le noeud TSN
docker run -d -p 8080:8080 mytsn