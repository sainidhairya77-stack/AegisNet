# ==============================================================================
# AegisNet Full-Stack Production Dockerfile (Frontend UI + FastAPI Backend)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build React Frontend (Vite)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci || npm install

COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Build Python Dependencies
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS python-builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 3: Final Production Runtime (FastAPI + Embedded UI)
# ------------------------------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH \
    PYTHONPATH=/app/backend:/app

# Install runtime libraries for PostgreSQL, Scapy packet sniffing, and curl healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages
COPY --from=python-builder /root/.local /root/.local

# Copy backend code
COPY backend/ /app/backend/
COPY backend/app/ /app/app/

# Copy compiled frontend assets from Stage 1 into paths checked by backend/app/main.py
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY --from=frontend-builder /app/frontend/dist /app/dist

# Create persistent storage directories
RUN mkdir -p /app/data/uploads /app/data/samples /app/data/models /app/logs

# Health check
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/health || exit 1

# Start FastAPI server on Render's dynamic PORT or default 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
