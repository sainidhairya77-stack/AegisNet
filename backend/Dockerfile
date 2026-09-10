# Multi-stage production build for AegisNet Backend (FastAPI + Scapy + ML)
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies and compilation tools for Scapy / C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies into user directory
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final runtime image
FROM python:3.12-slim

WORKDIR /app

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH

# Install minimal runtime dependencies (Postgres client library, curl for healthcheck, libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy backend application source
COPY . .

# Create persistent storage directories
RUN mkdir -p /app/data/uploads /app/data/samples /app/data/models /app/logs

EXPOSE 8000

# Health check against live endpoint
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

# Start FastAPI via uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
