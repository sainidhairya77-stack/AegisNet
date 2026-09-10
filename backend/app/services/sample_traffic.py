"""
Sample Attack Traffic Generator using Scapy.

Constructs realistic cybersecurity scenarios representing multi-stage APT campaigns:
1. External Port Reconnaissance
2. SSH Credential Brute Forcing
3. Web App Exploitation (DMZ)
4. Lateral Movement to Internal Database
5. High-Volume Reverse Tunnel Exfiltration
"""

import os
from pathlib import Path
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, wrpcap


def generate_apt29_scenario_pcap(output_path: str = "data/samples/apt29_scenario.pcap") -> str:
    """Generate a realistic multi-stage APT attack scenario PCAP."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    packets = []
    
    attacker_ip = "198.51.100.42"
    dmz_web_ip = "10.0.0.15"
    core_db_ip = "10.0.0.99"
    gateway_ip = "10.0.0.1"
    
    # 1. External Port Reconnaissance (Port Scan)
    recon_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    for sport_idx, port in enumerate(recon_ports):
        packets.append(
            Ether()
            / IP(src=attacker_ip, dst=dmz_web_ip)
            / TCP(sport=51000 + sport_idx, dport=port, flags="S")
        )
        if port not in (80, 443, 22):
            # Closed port sends RST/ACK
            packets.append(
                Ether()
                / IP(src=dmz_web_ip, dst=attacker_ip)
                / TCP(sport=port, dport=51000 + sport_idx, flags="RA")
            )
        else:
            # Open port sends SYN/ACK
            packets.append(
                Ether()
                / IP(src=dmz_web_ip, dst=attacker_ip)
                / TCP(sport=port, dport=51000 + sport_idx, flags="SA")
            )

    # 2. SSH Credential Brute Force (Failed Connection spikes)
    for i in range(15):
        packets.append(
            Ether()
            / IP(src=attacker_ip, dst=dmz_web_ip)
            / TCP(sport=52000 + i, dport=22, flags="S")
        )
        packets.append(
            Ether()
            / IP(src=dmz_web_ip, dst=attacker_ip)
            / TCP(sport=22, dport=52000 + i, flags="R")
        )

    # 3. Web Exploitation & Command Injection on HTTPS
    for i in range(10):
        payload = b"POST /api/v1/auth/login HTTP/1.1\r\nHost: portal.corp\r\nContent-Length: 48\r\n\r\n{\"user\":\"admin' OR '1'='1\",\"pass\":\"pwned\"}"
        packets.append(
            Ether()
            / IP(src=attacker_ip, dst=dmz_web_ip)
            / TCP(sport=53000 + i, dport=443, flags="PA")
            / payload
        )
        packets.append(
            Ether()
            / IP(src=dmz_web_ip, dst=attacker_ip)
            / TCP(sport=443, dport=53000 + i, flags="PA")
            / b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"compromised-session-token\"}"
        )

    # 4. Lateral Movement: Web Server pivots to Database
    for i in range(8):
        db_query = b"\x00\x00\x00\x38SELECT username, password_hash, ssn, credit_card FROM corporate_users;"
        packets.append(
            Ether()
            / IP(src=dmz_web_ip, dst=core_db_ip)
            / TCP(sport=49000 + i, dport=5432, flags="PA")
            / db_query
        )
        packets.append(
            Ether()
            / IP(src=core_db_ip, dst=dmz_web_ip)
            / TCP(sport=5432, dport=49000 + i, flags="PA")
            / (b"PGRES_RECORD_DATA_CONFIDENTIAL_PII" * 15)
        )

    # 5. Data Exfiltration via Reverse Tunnel on Port 4444 (ML Anomaly Trigger)
    for i in range(25):
        chunk = (f"ENCRYPTED_EXFIL_CHUNK_{i:04d}_DUMP_ARCHIVE".encode() * 40)
        packets.append(
            Ether()
            / IP(src=core_db_ip, dst=attacker_ip)
            / TCP(sport=5432, dport=4444, flags="PA")
            / chunk
        )

    # 6. Benign Background Traffic (DNS, Internal Gateway)
    for i in range(12):
        packets.append(
            Ether()
            / IP(src="10.0.0.22", dst=gateway_ip)
            / UDP(sport=58000 + i, dport=53)
            / b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07gateway\x04corp\x00\x00\x01\x00\x01"
        )
        packets.append(
            Ether()
            / IP(src="10.0.0.22", dst=dmz_web_ip)
            / TCP(sport=59000 + i, dport=80, flags="PA")
            / b"GET /health HTTP/1.1\r\nHost: internal.corp\r\n\r\n"
        )

    wrpcap(output_path, packets)
    return output_path
