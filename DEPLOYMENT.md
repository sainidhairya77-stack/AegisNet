# 🛡️ AegisNet: Production Deployment Guide

This guide covers deploying AegisNet as a containerized cyber defense platform using **Docker & Docker Compose** across:
1. **Cloud Linux VPS / AWS EC2 / DigitalOcean** (Recommended for public cloud deployment)
2. **Local Machine / Docker Desktop** (Windows / macOS / Linux)
3. **Custom Domain & Free SSL (Let's Encrypt / Certbot)**

---

## Architecture at a Glance

```
                              Public Internet
                                    │
                                    ▼ Port 80 / 443
                     ┌──────────────────────────────┐
                     │   aegisnet-frontend (Nginx)  │
                     │  - React SPA Static Assets   │
                     │  - Reverse Proxy for /auth,  │
                     │    /pcaps, /health           │
                     └──────────────┬───────────────┘
                                    │ (internal network)
                                    ▼ Port 8000
                     ┌──────────────────────────────┐
                     │   aegisnet-backend (FastAPI) │
                     │  - Scapy Packet Processor    │
                     │  - ML Isolation Forest       │
                     │  - OpenAI GPT-4o Copilot     │
                     └──────────────┬───────────────┘
                                    │ (internal network)
                                    ▼ Port 5432
                     ┌──────────────────────────────┐
                     │      aegisnet-postgres       │
                     │  - Relational Database       │
                     │  - Persistent Volume         │
                     └──────────────────────────────┘
```

---

## 🚀 Option 1: Cloud Deployment (AWS EC2 / Ubuntu VPS / DigitalOcean)

### Step 1: Launch a Virtual Machine (Instance)
- **OS**: Ubuntu 22.04 LTS or 24.04 LTS (x86_64)
- **Minimum Specs**: 2 vCPUs, 4 GB RAM, 25 GB SSD storage (e.g. AWS `t3.medium`, DigitalOcean `$24/mo` Droplet, or Hetzner `CPX21`).
- **Firewall / Security Group Rules**:
  | Port | Protocol | Source | Description |
  | :--- | :--- | :--- | :--- |
  | `22` | TCP | Your IP | SSH Access |
  | `80` | TCP | `0.0.0.0/0` | HTTP (Frontend Dashboard) |
  | `443` | TCP | `0.0.0.0/0` | HTTPS (SSL Encrypted Web UI) |
  | `8001` | TCP | `0.0.0.0/0` | Backend API / Swagger Docs (Optional) |

---

### Step 2: Connect to your Server via SSH
```bash
ssh ubuntu@YOUR_SERVER_IP
```

---

### Step 3: Clone the AegisNet Repository
```bash
git clone https://github.com/sainidhairya77-stack/AegisNet.git
cd AegisNet
```

---

### Step 4: Run the 1-Click Automated Deployment Script
We have included a fully automated script `deploy.sh` that checks/installs Docker, generates cryptographic secrets, and brings up the stack:

```bash
chmod +x deploy.sh
./deploy.sh
```

The script will automatically:
1. Detect and install Docker and Docker Compose (if not already installed).
2. Create `.env` with a unique, cryptographically strong `JWT_SECRET` and database password.
3. Build the Nginx frontend and FastAPI backend images.
4. Launch all 3 containers (`aegisnet-postgres`, `aegisnet-backend`, `aegisnet-frontend`).
5. Verify health status and output your live access URL!

---

### Step 5: Access the Live Application
Open your browser and visit:
👉 **`http://YOUR_SERVER_IP`**

Log in using the demo account or register a new administrator account.

---

## 💻 Option 2: Local Windows / macOS (Docker Desktop)

### Prerequisites:
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and make sure it is running.

### Quick Start on Windows:
1. Open the `AegisNet` folder.
2. Double-click **`deploy.bat`**.
3. Once completed, open:
   - Dashboard: **`http://localhost:80`**
   - API Docs: **`http://localhost:8001/docs`**

### Quick Start via Terminal (macOS / Linux / WSL):
```bash
# 1. Copy environment template
cp .env.docker.example .env

# 2. Build and start containers
docker compose up -d --build

# 3. View status
docker compose ps
```

---

## 🔒 Adding a Custom Domain & Free SSL (HTTPS)

To run AegisNet on `https://your-domain.com`:

### Method A: Using Certbot (Standalone Nginx SSL)
1. Point your domain's DNS `A` record to `YOUR_SERVER_IP`.
2. Stop the frontend container temporarily to free port 80:
   ```bash
   docker compose stop frontend
   ```
3. Install Certbot and generate certificates:
   ```bash
   sudo apt-get update && sudo apt-get install -y certbot
   sudo certbot certonly --standalone -d your-domain.com
   ```
4. Map the generated `/etc/letsencrypt` folder into `docker-compose.yml` and enable SSL in `frontend/nginx.conf`.
5. Restart the containers:
   ```bash
   docker compose up -d frontend
   ```

### Method B: Using Cloudflare (Zero-Config HTTPS - Recommended)
1. Add your domain to [Cloudflare](https://www.cloudflare.com) (Free Tier).
2. Point an `A` record (`@` or `soc`) to `YOUR_SERVER_IP`.
3. Set SSL/TLS encryption mode to **"Flexible"** or **"Full"**.
4. Now, accessing `https://your-domain.com` will automatically be secured with a free, valid SSL certificate with zero server configuration needed!

---

## ⚙️ Environment Variables Reference (`.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `FRONTEND_PORT` | `80` | Host port for the Web UI |
| `BACKEND_PORT` | `8001` | Host port for the FastAPI backend |
| `POSTGRES_HOST_PORT`| `5433` | Host port for PostgreSQL (avoids conflict with local 5432) |
| `POSTGRES_USER` | `aegisnet` | Database username |
| `POSTGRES_PASSWORD` | auto-generated | Database password |
| `POSTGRES_DB` | `aegisnet` | Database name |
| `JWT_SECRET` | auto-generated | Secret key for signing authentication tokens |
| `OPENAI_API_KEY` | *(empty)* | Optional: OpenAI key for GPT-4o Copilot |
| `OPENAI_MODEL` | `gpt-4o` | Model name for AI investigations |

---

## 🛠️ Common Operations & Maintenance

### Check Logs
```bash
# View all container logs
docker compose logs -f

# View backend logs only
docker compose logs -f backend

# View frontend / Nginx access logs
docker compose logs -f frontend
```

### Restart Services
```bash
docker compose restart
```

### Stop Application
```bash
docker compose down
```

### Updating Code & Redeploying
```bash
git pull origin main
docker compose up -d --build
```

### Database Backup
```bash
docker compose exec postgres pg_dump -U aegisnet aegisnet > backup_$(date +%F).sql
```
