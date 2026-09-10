#!/usr/bin/env bash
# ==============================================================================
# AegisNet - Automated Production Deployment Script (Linux / AWS EC2 / VPS)
# ==============================================================================
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================"
echo -e "       🛡️  AegisNet Cyber Defense Platform"
echo -e "       Automated Docker Production Deployment"
echo -e "======================================================${NC}\n"

# 1. Check Docker Installation
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[!] Docker not found. Installing Docker using official script...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    echo -e "${GREEN}[✓] Docker installed successfully.${NC}"
fi

# 2. Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo -e "${RED}[ERROR] docker compose (v2) is required but not installed.${NC}"
    echo "Please install Docker Compose plugin: sudo apt-get install docker-compose-plugin"
    exit 1
fi

# 3. Setup Environment Variables
if [ ! -f .env ]; then
    echo -e "${YELLOW}[i] No .env file found. Generating from .env.docker.example...${NC}"
    cp .env.docker.example .env
    
    # Generate random JWT secret if openssl is available
    if command -v openssl &> /dev/null; then
        RANDOM_JWT=$(openssl rand -hex 32)
        RANDOM_DB_PASS=$(openssl rand -hex 16)
        # Cross-platform sed replace
        sed -i.bak "s/replace_with_a_64_character_random_hex_string_for_production_jwt/${RANDOM_JWT}/g" .env
        sed -i.bak "s/replace_with_a_strong_database_password_1234/${RANDOM_DB_PASS}/g" .env
        rm -f .env.bak
        echo -e "${GREEN}[✓] Generated unique secure JWT secret and DB password in .env${NC}"
    fi
fi

# 4. Create necessary local directories
mkdir -p data/uploads data/samples data/models logs

# 5. Build and Start Containers
echo -e "\n${CYAN}[1/3] Building and starting AegisNet Docker containers...${NC}"
docker compose down --remove-orphans || true
docker compose build --pull
docker compose up -d

# 6. Wait for Healthchecks
echo -e "\n${CYAN}[2/3] Waiting for services to become healthy...${NC}"
RETRIES=30
until [ "$(docker inspect -f '{{.State.Health.Status}}' aegisnet-backend 2>/dev/null)" == "healthy" ] || [ $RETRIES -le 0 ]; do
    echo -n "."
    sleep 3
    RETRIES=$((RETRIES - 1))
done
echo ""

if [ $RETRIES -le 0 ]; then
    echo -e "${YELLOW}[!] Warning: Backend healthcheck is taking longer than expected.${NC}"
    echo "Check container logs using: docker compose logs backend"
else
    echo -e "${GREEN}[✓] Backend and Database are healthy!${NC}"
fi

# 7. Print Deployment Summary
PUBLIC_IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')

echo -e "\n${GREEN}======================================================"
echo -e "       🎉 AegisNet Deployed Successfully!"
echo -e "======================================================${NC}"
echo -e "  🌐 Web UI Dashboard : ${CYAN}http://${PUBLIC_IP}:80${NC} (or http://localhost:80)"
echo -e "  🔌 Backend API Docs : ${CYAN}http://${PUBLIC_IP}:8001/docs${NC}"
echo -e "  📊 Health Check     : ${CYAN}http://${PUBLIC_IP}:8001/health${NC}"
echo -e "\nUseful Commands:"
echo -e "  View logs        : ${YELLOW}docker compose logs -f${NC}"
echo -e "  Stop containers  : ${YELLOW}docker compose down${NC}"
echo -e "  Restart stack    : ${YELLOW}docker compose restart${NC}"
echo -e "======================================================\n"
