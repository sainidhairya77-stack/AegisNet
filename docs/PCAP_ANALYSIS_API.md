# PCAP Analysis API Documentation

## Overview

The AegisNet PCAP Analysis API provides a complete workflow for network threat detection:
1. **Upload** a PCAP file
2. **Analyze** to extract flows and detect anomalies
3. **Review** alerts, incidents, and risk scores
4. **Map** observed network topology and attack paths

## Complete Workflow

### 1. Upload PCAP File

```bash
curl -X POST http://localhost:8000/pcaps/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@network_traffic.pcap"
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "original_filename": "network_traffic.pcap",
  "file_size": 1048576,
  "sha256_hash": "abc123...",
  "status": "UPLOADED",
  "uploader_id": "user-uuid",
  "uploaded_at": "2024-01-15T10:30:00Z"
}
```

### 2. Analyze PCAP File

Triggers the full detection pipeline:

```bash
curl -X POST http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"
```

**Analysis Pipeline:**
1. Parse PCAP packets (TCP/UDP/ICMP/IPv6 support)
2. Aggregate into network flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
3. Extract statistical features for ML
4. Run 4 rule-based detection rules:
   - **Port Scan Detection**: >10 unique ports to same destination
   - **High Connection Rate**: >50 flows in <60 seconds
   - **Failed Connection Detection**: >10 RST/SYN-only patterns
   - **Suspicious Outbound**: >1MB to external IPs
5. Run ML Anomaly Detection (Isolation Forest)
6. Correlate related alerts into incidents
7. Calculate risk scores with asset criticality adjustment

**Response:**
```json
{
  "pcap_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "statistics": {
    "flow_count": 1024,
    "alert_count": 42,
    "incident_count": 5,
    "rule_alerts": 28,
    "ml_alerts": 14
  },
  "incidents": [
    {
      "id": "incident-uuid",
      "title": "Correlated Incident: Port Scan Detection + High Connection Rate",
      "risk_score": 87.5,
      "severity": "HIGH",
      "alert_count": 4
    }
  ],
  "message": "Analysis complete: 1024 flows, 42 alerts, 5 incidents"
}
```

### 3. Retrieve Network Flows

```bash
curl -X GET http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/flows \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"
```

**Query Parameters:**
- `limit`: Number of results (default: 100, max: 1000)
- `offset`: Pagination offset (default: 0)

**Response:**
```json
{
  "pcap_id": "123e4567-e89b-12d3-a456-426614174000",
  "total_flows": 1024,
  "flows": [
    {
      "id": "flow-uuid",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.1",
      "source_port": 54321,
      "destination_port": 443,
      "protocol": "TCP",
      "packet_count": 127,
      "byte_count": 65536,
      "duration_seconds": 30.5
    }
  ]
}
```

### 4. Retrieve Detected Alerts

```bash
curl -X GET http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/alerts \
  -H "Authorization: Bearer <token>"
```

**Query Parameters:**
- `limit`: Number of results (default: 100, max: 1000)
- `offset`: Pagination offset (default: 0)
- `severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)

**Response:**
```json
{
  "pcap_id": "123e4567-e89b-12d3-a456-426614174000",
  "total_alerts": 42,
  "alerts": [
    {
      "id": "alert-uuid",
      "rule_name": "Port Scan Detection",
      "description": "Potential port scan: 192.168.1.100 contacted 10.0.0.1 on 15 different ports",
      "severity": "HIGH",
      "confidence": 0.95,
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.1",
      "triggered_at": "2024-01-15T10:31:00Z"
    }
  ]
}
```

### 5. Retrieve Correlated Incidents

```bash
curl -X GET http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/incidents \
  -H "Authorization: Bearer <token>"
```

**Query Parameters:**
- `limit`: Number of results (default: 50, max: 500)
- `offset`: Pagination offset (default: 0)

**Response:**
```json
{
  "pcap_id": "123e4567-e89b-12d3-a456-426614174000",
  "total_incidents": 5,
  "incidents": [
    {
      "id": "incident-uuid",
      "title": "Correlated Incident: Port Scan Detection + High Connection Rate",
      "description": "Incident with 4 correlated alerts:\n- Potential port scan detected\n- High connection rate detected\n- ... and 2 more alerts",
      "severity": "HIGH",
      "risk_score": 87.5,
      "alert_count": 4,
      "source_ips": ["192.168.1.100"],
      "destination_ips": ["10.0.0.1"],
      "detected_at": "2024-01-15T10:31:00Z",
      "created_at": "2024-01-15T10:35:00Z"
    }
  ]
}
```

### 6. Retrieve Network Topology Graph

Builds an observed graph from analyzed network flows:

```bash
curl -X GET http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/graph \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "nodes": [
    {
      "id": "192.168.1.100",
      "ip": "192.168.1.100",
      "label": "192.168.1.100",
      "type": "internal",
      "risk_level": "MEDIUM"
    }
  ],
  "edges": [
    {
      "source": "192.168.1.100",
      "target": "10.0.0.1",
      "protocol": "TCP",
      "ports": [443],
      "connection_count": 12,
      "suspicious": true
    }
  ]
}
```

### 7. Analyze Incident Attack Paths

Finds observed paths from incident source IPs to critical or high-value assets. If no critical asset is configured, the incident destination IPs are used as targets.

```bash
curl -X POST http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/incidents/incident-uuid/attack-paths \
  -H "Authorization: Bearer <token>"
```

Previously calculated paths can be retrieved with:

```bash
curl -X GET http://localhost:8000/pcaps/123e4567-e89b-12d3-a456-426614174000/incidents/incident-uuid/attack-paths \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
[
  {
    "id": "attack-path-uuid",
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.10",
    "path_nodes": ["192.168.1.100", "10.0.0.1", "10.0.0.10"],
    "path_edges": [
      {
        "source": "192.168.1.100",
        "target": "10.0.0.1",
        "protocols": ["TCP"],
        "ports": [443],
        "connection_count": 12
      }
    ],
    "risk_score": 92.5,
    "description": "Observed path from 192.168.1.100 to 10.0.0.10 through 3 nodes"
  }
]
```

## Authentication

All endpoints require Bearer token authentication:

```bash
Authorization: Bearer <JWT_TOKEN>
```

### Get Token

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "user-uuid",
    "username": "analyst",
    "role": "ANALYST"
  }
}
```

## Role-Based Access Control

| Endpoint | VIEWER | ANALYST | ADMIN |
|----------|--------|---------|-------|
| POST /pcaps/upload | ❌ | ✅ | ✅ |
| POST /pcaps/{id}/analyze | ❌ | ✅ | ✅ |
| GET /pcaps | ✅ | ✅ | ✅ |
| GET /pcaps/{id}/flows | ✅ | ✅ | ✅ |
| GET /pcaps/{id}/alerts | ✅ | ✅ | ✅ |
| GET /pcaps/{id}/incidents | ✅ | ✅ | ✅ |
| GET /pcaps/{id}/graph | ✅ | ✅ | ✅ |
| POST /pcaps/{id}/incidents/{incident_id}/attack-paths | ❌ | ✅ | ✅ |
| GET /pcaps/{id}/incidents/{incident_id}/attack-paths | ✅ | ✅ | ✅ |

## Detection Engines

### Rule-Based Detection

Rule-based detection uses hardcoded patterns to identify known attack signatures:

1. **Port Scan Detection**
   - Detects when a single source IP contacts many destination ports on the same target
   - Threshold: >10 unique destination ports
   - Severity: MEDIUM
   - Confidence: 0.5 + (unique_ports × 0.05), max 0.95

2. **High Connection Rate Detection**
   - Detects rapid connection establishment patterns
   - Threshold: >50 flows from same source in <60 seconds
   - Severity: MEDIUM
   - Confidence: Based on flow rate intensity

3. **Failed Connection Detection**
   - Detects patterns of failed connection attempts
   - Threshold: >10 flows with RST or SYN-only flags
   - Severity: LOW
   - Confidence: 0.6 + (failed_count × 0.02), max 0.9

4. **Suspicious Outbound Traffic Detection**
   - Detects large data exfiltration attempts
   - Threshold: >1MB of outbound data to external IPs
   - Severity: HIGH
   - Confidence: 0.8 + (size_factor × 0.1), max 0.95

### Machine Learning Detection

ML-based detection uses Isolation Forest to identify anomalous flow patterns:

**Features:**
- Packet count per flow
- Byte count per flow
- Flow duration (seconds)
- Source port
- Destination port
- Unique destination ports per source IP
- Average packet size
- Flow rate (packets/second)

**Preprocessing:**
- StandardScaler normalization
- NaN value handling

**Anomaly Scoring:**
- Isolation Forest contamination: 15%
- Raw scores (-1 to 1) normalized to 0-100 scale
- Alert threshold: 70/100

**Confidence Calculation:**
- confidence = (anomaly_score / 100) × 0.95
- Range: 0.0 to 0.95

### Incident Correlation

Alerts are automatically correlated into incidents using:

1. **Temporal Correlation**
   - Time window: 3600 seconds (1 hour)
   - Alerts within the same hour are candidates for correlation

2. **IP Correlation**
   - Alerts sharing source or destination IPs are grouped
   - Shared IP threshold: At least 1 common IP address

3. **Automatic Incident Creation**
   - Grouped alerts automatically create an incident
   - Incident severity = highest severity of grouped alerts
   - Incident risk score = weighted average of alert risks

### Risk Scoring

Risk scores combine multiple factors (0-100 scale):

$$\text{Risk Score} = (\text{Avg Alert Risk} \times 0.6) + (\text{Alert Count Boost} \times 0.2) + (\text{Criticality Boost} \times 0.2)$$

**Where:**
- **Avg Alert Risk**: Average risk across all alerts
- **Alert Count Boost**: +2% per alert, max +20%
- **Criticality Boost**: Based on asset criticality levels
  - CRITICAL asset: +30
  - HIGH asset: +20
  - MEDIUM asset: +10

**Severity Mapping:**
- Risk 90-100: **CRITICAL**
- Risk 70-89: **HIGH**
- Risk 50-69: **MEDIUM**
- Risk 0-49: **LOW**

## Error Handling

All endpoints return appropriate HTTP status codes:

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found (PCAP/incident not found) |
| 500 | Server error (analysis failed) |

**Error Response Format:**
```json
{
  "detail": "Description of the error"
}
```

## Example: Complete Analysis Workflow

```bash
#!/bin/bash

# 1. Register and login
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst",
    "password": "password123"
  }' | jq -r '.access_token')

# 2. Upload PCAP file
PCAP_ID=$(curl -s -X POST http://localhost:8000/pcaps/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample.pcap" | jq -r '.id')

echo "PCAP ID: $PCAP_ID"

# 3. Analyze PCAP
curl -X POST http://localhost:8000/pcaps/$PCAP_ID/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# 4. Get analysis results
curl -X GET http://localhost:8000/pcaps/$PCAP_ID/incidents \
  -H "Authorization: Bearer $TOKEN" | jq '.'

# 5. Get detailed alerts
curl -X GET "http://localhost:8000/pcaps/$PCAP_ID/alerts?severity=HIGH" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

## Performance Considerations

- **PCAP Size Limits**: Recommend <100MB for fast analysis
- **Memory Usage**: ML detection requires loading all flows into memory
- **Processing Time**: Typically <30 seconds for 100MB PCAP (varies by system)
- **Database Indexes**: Ensure indexes on pcap_file_id and triggered_at for query performance

## Future Enhancements

- Async analysis with job queue (Celery/RQ)
- Real-time streaming PCAP analysis
- Custom rule builder UI
- ML model fine-tuning based on known threats
- Graph-based attack path visualization
- Automatic firewall rule generation
