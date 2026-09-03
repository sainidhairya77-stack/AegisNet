# AegisNet

**AI-Assisted Network Defense, Attack Path Analysis & Controlled Automated Response Platform**

A comprehensive cybersecurity platform for analyzing network traffic, detecting suspicious behavior, investigating incidents with AI assistance, and simulating defensive responses.

## Overview

AegisNet helps security analysts:

1. **Analyze** network traffic from PCAP files
2. **Extract** meaningful network features and flows
3. **Detect** suspicious behavior using rules and machine learning
4. **Correlate** related detections into incidents
5. **Visualize** network topology and attack paths
6. **Investigate** incidents with AI assistance
7. **Simulate** defensive actions before executing
8. **Execute** controlled responses through secure firewall connector
9. **Audit** all security-sensitive actions

## Key Features

### Network Analysis
- PCAP file parsing and processing
- Network flow aggregation
- Feature extraction (packet rates, connection patterns, etc.)
- Protocol analysis

### Detection Engine
- Rule-based detection (port scans, brute force, high connection rates, etc.)
- Machine learning anomaly detection (Isolation Forest)
- Risk scoring and severity assessment

### Incident Management
- Automatic incident correlation
- Timeline tracking
- Evidence aggregation
- Status management

### Network Visualization
- Network topology graph using NetworkX
- Attack path analysis
- Asset criticality levels

### AI Investigation
- OpenAI integration for natural language investigation
- Structured evidence gathering
- Recommendations and analysis

### Defensive Operations
- What-if simulation (Digital Twin)
- Response request workflow with approval
- Blocklist management
- Mock firewall for safe testing

## Architecture

```
                    Frontend (React/TypeScript)
                            |
                            v
                    FastAPI Backend
                            |
            +---------------+----------------+
            |               |                |
            v               v                v
        PostgreSQL      Analysis Engine   OpenAI
                            |
            +-------+-------+-------+-------+
            |       |       |       |       |
            v       v       v       v       v
          PCAP   Rules    ML     Graphs  Response
```

## Technology Stack

### Backend
- **Python 3.12+**
- **FastAPI** - Web framework
- **PostgreSQL** - Database
- **SQLAlchemy** - ORM
- **Scapy** - Packet analysis
- **scikit-learn** - Machine learning
- **NetworkX** - Graph analysis
- **OpenAI API** - AI integration

### Frontend
- **React 18**
- **TypeScript**
- **Vite** - Build tool

### DevOps
- **Docker & Docker Compose**

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL 16+ (or Docker)
- Node.js 18+ (for frontend)
- OpenAI API key (optional)

### Local Development Setup

1. **Clone and setup backend:**
```bash
cd backend
cp .env.example .env
# Edit .env with your configuration
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Setup database:**
```bash
# Option A: Using Docker
docker-compose up -d postgres

# Option B: Local PostgreSQL
createdb -U postgres aegisnet
```

3. **Run backend:**
```bash
uvicorn app.main:app --reload
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

4. **Setup frontend:**
```bash
cd frontend
npm install
npm run dev
# Frontend available at http://localhost:5173
```

### Docker Setup

```bash
# Start all services
docker-compose up --build

# Stop services
docker-compose down
```

Services:
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- PostgreSQL: localhost:5432

## Configuration

### Environment Variables

Create `.env` file from `.env.example`:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/aegisnet

# JWT
JWT_SECRET=your-secret-key-min-32-chars
JWT_EXPIRATION_HOURS=24

# API
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=["http://localhost:3000"]

# OpenAI (optional)
OPENAI_API_KEY=sk-...

# Firewall
FIREWALL_MODE=mock  # or linux

# File Upload
MAX_UPLOAD_SIZE_MB=1000
UPLOAD_DIR=./data/uploads
```

## API Documentation

### Authentication
```bash
# Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"SecurePass123"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"SecurePass123"}'

# Get current user
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/auth/me
```

### Interactive API Docs
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Usage Workflow

### 1. Register and Login
Create an account and authenticate

### 2. Upload PCAP
Upload network traffic capture for analysis

### 3. Analyze Traffic
System automatically:
- Parses packets
- Extracts network flows
- Applies detection rules
- Runs ML anomaly detection
- Calculates risk scores
- Correlates alerts into incidents

### 4. Investigate
- View incident details
- Ask AI questions about the incident
- Review evidence and timeline
- Examine network topology and attack paths

### 5. Simulate Response
- Run What-if simulations
- Test defensive actions impact
- Review blocked paths and affected assets

### 6. Approve and Execute
- Request defensive action
- Get analyst/admin approval
- Execute through firewall connector
- Track in audit log

## Project Structure

```
AegisNet/
├── backend/
│   ├── app/
│   │   ├── api/           # API routes
│   │   ├── models.py      # Database models
│   │   ├── schemas.py     # Pydantic schemas
│   │   ├── config.py      # Configuration
│   │   ├── database.py    # Database setup
│   │   ├── security.py    # Authentication
│   │   ├── main.py        # FastAPI app
│   │   └── utils/         # Utilities
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## Testing

```bash
# Run tests
pytest backend/tests -v

# With coverage
pytest --cov=app backend/tests
```

## Security Notes

- Default uses mock firewall (FIREWALL_MODE=mock)
- Production firewall integration requires Linux lab environment
- Real firewall NOT exposed to public internet
- All secrets stored in environment variables
- Passwords hashed with bcrypt
- JWT tokens with expiration
- RBAC with ADMIN/ANALYST/VIEWER roles
- Comprehensive audit logging

## Deployment

### Local Development
```bash
docker-compose up
```

### Cloud Deployment (Recommended)
- Use FIREWALL_MODE=mock (default)
- Deploy backend on cloud platform (AWS, GCP, Azure, etc.)
- Deploy PostgreSQL managed service
- Deploy frontend on CDN
- Never expose production firewall

### Private Lab (Linux Firewall)
- Use FIREWALL_MODE=linux
- Deploy on private network
- Only for authorized defensive testing

## Documentation

See [docs/](docs/) directory:
- [Architecture](docs/architecture.md)
- [Detection Engine](docs/detection-engine.md)
- [ML Pipeline](docs/ml-pipeline.md)
- [AI Investigator](docs/ai-investigator.md)
- [Attack Path](docs/attack-path.md)
- [Digital Twin](docs/digital-twin.md)
- [Response Engine](docs/response-engine.md)
- [Firewall Connector](docs/firewall-connector.md)
- [Security](docs/security.md)
- [Deployment](docs/deployment.md)

## Limitations

- Encrypted traffic visibility limited to metadata
- Anomaly detection based on statistical patterns
- Attack paths based on observed connectivity (not proof)
- Mock firewall is simulation only
- Requires analyst validation before real responses
- PCAP analysis limited to captured traffic

## Future Improvements

- Zeek/Suricata integration
- SIEM/EDR integration
- Streaming network telemetry
- Supervised attack classification
- Threat intelligence feeds
- MITRE ATT&CK mapping
- Kafka message queue
- Advanced profiling and monitoring

## Contributing

This project is intended as a portfolio demonstration. Contributions welcome for bug fixes and documentation improvements.

## License

MIT License - See LICENSE file

## Support

For issues and questions, please open an issue in the repository.

---

**Built with security, automation, and AI in mind.**
