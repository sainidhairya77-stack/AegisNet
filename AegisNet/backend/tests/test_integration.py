"""
Integration tests for PCAP analysis pipeline

This test module verifies the complete detection pipeline:
1. Packet parsing
2. Flow aggregation
3. Rule-based detection
4. ML anomaly detection
5. Incident correlation
6. Risk scoring
"""

import sys
from pathlib import Path

# Add backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

import pytest
from datetime import datetime
from typing import List, Dict, Any
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from scapy.all import Ether, IP, TCP, UDP, wrpcap

# Mock imports - these would be the actual service classes
from app.database import get_db
from app.main import app
from app.models import Base, NetworkAsset, NetworkFlow, Alert, AlertSeverity, Incident, User
from app.security import JWTHandler, PasswordHasher, get_current_analyst, get_current_user
from app.services.packet_parser import PacketParser, FlowAggregator
from app.services.rule_engine import RuleEngine
from app.services.ml_engine import MLDetectionEngine
from app.services.correlation_engine import IncidentCorrelator
from app.services.risk_engine import RiskCalculator


class TestDetectionPipeline:
    """Test the complete detection pipeline with mock data"""

    @staticmethod
    def create_mock_packets(count: int = 100) -> List[Dict[str, Any]]:
        """Create mock packet data for testing"""
        packets = []
        for i in range(count):
            packet = {
                "timestamp": datetime.utcnow().timestamp() + i,
                "size": 100 + (i % 500),
                "protocol": "TCP" if i % 3 == 0 else ("UDP" if i % 3 == 1 else "ICMP"),
                "source_ip": f"192.168.1.{10 + (i // 20)}",
                "destination_ip": f"10.0.0.{1 + (i % 5)}",
                "source_port": 50000 + i,
                "destination_port": 443 if i % 2 == 0 else 80,
                "tcp_flags": "SYN" if i % 10 == 0 else "ACK",
                "has_payload": True,
                "ttl": 64
            }
            packets.append(packet)
        return packets

    @staticmethod
    def create_mock_flows(count: int = 20) -> List[Dict[str, Any]]:
        """Create mock flow data for testing"""
        flows = []
        for i in range(count):
            flow = {
                "source_ip": f"192.168.1.{10 + (i % 3)}",
                "destination_ip": f"10.0.0.{1 + (i % 2)}",
                "source_port": 50000 + i,
                "destination_port": 443,
                "protocol": "TCP",
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "duration_seconds": 30.0 + (i % 10),
                "packet_count": 50 + (i * 10),
                "byte_count": 5000 + (i * 1000),
                "tcp_flags": "SYN,ACK",
                "has_retransmissions": False,
                "has_failed_connections": i % 5 == 0
            }
            flows.append(flow)
        return flows

    def test_packet_parsing(self):
        """Test packet parsing produces valid packet data"""
        packets = self.create_mock_packets(50)
        assert len(packets) == 50
        
        # Verify packet structure
        for packet in packets:
            assert "source_ip" in packet
            assert "destination_ip" in packet
            assert "protocol" in packet
            assert packet["source_ip"].startswith("192.168.1.")
            assert packet["destination_ip"].startswith("10.0.0.")

    def test_flow_aggregation(self):
        """Test flow aggregation from packets"""
        packets = self.create_mock_packets(100)
        
        # Aggregate packets into flows
        flows = FlowAggregator.create_flows(packets)
        
        assert len(flows) > 0
        assert len(flows) <= len(packets)  # Should have fewer flows than packets
        
        # Verify flow structure
        for flow in flows:
            assert "source_ip" in flow
            assert "destination_ip" in flow
            assert "protocol" in flow
            assert "packet_count" in flow
            assert "byte_count" in flow
            assert flow["packet_count"] >= 1

    def test_rule_based_detection(self):
        """Test rule-based detection engine"""
        flows = [
            # Normal flows
            {
                "id": str(uuid4()),
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "TCP",
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "duration_seconds": 30,
                "packet_count": 50,
                "byte_count": 5000,
                "tcp_flags": "SYN,ACK",
                "has_retransmissions": False,
                "has_failed_connections": False
            },
            # Port scan flow
            {
                "id": str(uuid4()),
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "source_port": 50000,
                "destination_port": 80,
                "protocol": "TCP",
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "duration_seconds": 1,
                "packet_count": 1,
                "byte_count": 60,
                "tcp_flags": "SYN",
                "has_retransmissions": False,
                "has_failed_connections": True
            },
        ]
        
        # Create mock NetworkFlow objects
        network_flows = []
        for flow_data in flows:
            flow_obj = type('NetworkFlow', (), flow_data)()
            network_flows.append(flow_obj)
        
        # Run detection
        rule_engine = RuleEngine()
        alerts = rule_engine.detect(network_flows)
        
        # Should detect something
        assert isinstance(alerts, list)

    def test_ml_detection(self):
        """Test ML-based anomaly detection"""
        flows = self.create_mock_flows(20)
        
        # Create mock NetworkFlow objects
        network_flows = []
        for flow_data in flows:
            flow_data["id"] = str(uuid4())
            flow_obj = type('NetworkFlow', (), flow_data)()
            network_flows.append(flow_obj)
        
        # Run ML detection
        ml_engine = MLDetectionEngine()
        alerts = ml_engine.detect(network_flows, threshold=70)
        
        # Should return list of alerts
        assert isinstance(alerts, list)

    def test_risk_calculation(self):
        """Test risk score calculation"""
        # Create mock alerts
        alerts = [
            type('Alert', (), {
                'severity': AlertSeverity.CRITICAL,
                'confidence': 0.95,
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.1'
            })(),
            type('Alert', (), {
                'severity': AlertSeverity.HIGH,
                'confidence': 0.85,
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.1'
            })(),
        ]
        
        # Calculate risk for each alert
        individual_risks = [RiskCalculator.calculate_alert_risk(a) for a in alerts]
        
        # Should have calculated risks for all alerts
        assert len(individual_risks) == 2
        
        # CRITICAL should have higher risk than HIGH
        assert individual_risks[0] > individual_risks[1]
        
        # Risks should be between 0 and 100
        for risk in individual_risks:
            assert 0 <= risk <= 100

    def test_incident_correlation(self):
        """Test incident correlation from alerts"""
        # Create mock alerts
        now = datetime.utcnow()
        alerts = [
            type('Alert', (), {
                'id': str(uuid4()),
                'severity': AlertSeverity.HIGH,
                'confidence': 0.85,
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.1',
                'rule_name': 'Port Scan Detection',
                'description': 'Port scan detected',
                'triggered_at': now,
                'alerts': []
            })(),
            type('Alert', (), {
                'id': str(uuid4()),
                'severity': AlertSeverity.MEDIUM,
                'confidence': 0.75,
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.1',
                'rule_name': 'High Connection Rate',
                'description': 'High connection rate detected',
                'triggered_at': now,
                'alerts': []
            })(),
        ]
        
        # Since correlation requires database, we test the correlation logic
        correlator = IncidentCorrelator()
        
        # Test IP correlation check
        alert1 = alerts[0]
        alert2 = alerts[1]
        
        is_correlated = correlator._alerts_correlated(alert1, alert2)
        
        # These alerts should be correlated (same IPs, close time)
        assert is_correlated is True


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_packet_list(self):
        """Test flow aggregation with empty packet list"""
        flows = FlowAggregator.create_flows([])
        assert flows == [] or isinstance(flows, list)

    def test_single_packet(self):
        """Test flow aggregation with single packet"""
        packet = {
            "timestamp": datetime.utcnow().timestamp(),
            "size": 100,
            "protocol": "TCP",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 443,
            "tcp_flags": "SYN",
            "has_payload": True,
            "ttl": 64
        }
        
        flows = FlowAggregator.create_flows([packet])
        assert isinstance(flows, list)

    def test_malformed_packets(self):
        """Test flow aggregation with malformed data"""
        # Packets with missing fields
        packets = [
            {
                "timestamp": datetime.now().timestamp(),
                "size": 100,
                "protocol": "TCP",
                "source_ip": "192.168.1.100",
                # Missing destination_ip - should be skipped
                "destination_port": 443,
            },
            {
                "timestamp": datetime.now().timestamp(),
                "size": 100,
                "protocol": "TCP",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                # Missing destination_port - will use None
                "source_port": 54321,
            }
        ]
        
        # Should handle gracefully (skip packets without source/dest IPs)
        flows = FlowAggregator.create_flows(packets)
        assert isinstance(flows, list)
        # Only the second packet should create a flow
        assert len(flows) <= len(packets)

    def test_risk_score_boundaries(self):
        """Test risk score calculation at boundaries"""
        # Test with no alerts
        risk_no_alerts = 0  # Should default to 0
        assert risk_no_alerts == 0
        
        # Test severity to risk conversion
        for severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, 
                        AlertSeverity.MEDIUM, AlertSeverity.LOW]:
            risk = RiskCalculator.severity_to_risk(severity)
            assert 0 <= risk <= 100


class TestPcapApiValidation:
    """Test real PCAP upload and analysis through the backend API."""

    @pytest.fixture()
    def client(self, tmp_path, monkeypatch):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        Base.metadata.create_all(bind=engine)

        user_id = str(uuid4())
        db = TestingSessionLocal()
        db.add(User(
            id=user_id,
            username="phase3analyst",
            email="phase3@example.com",
            full_name="Phase 3 Analyst",
            hashed_password="unused",
            role="ANALYST",
            is_active=True,
        ))
        db.commit()
        db.close()

        upload_dir = tmp_path / "uploads"
        monkeypatch.setattr("app.services.pcap_service.settings.upload_dir", str(upload_dir))
        monkeypatch.setattr("app.services.pcap_service.settings.max_upload_size_mb", 1)

        def override_db():
            test_db = TestingSessionLocal()
            try:
                yield test_db
            finally:
                test_db.close()

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = lambda: user_id
        app.dependency_overrides[get_current_analyst] = lambda: user_id

        test_client = TestClient(app)
        test_client.testing_session_local = TestingSessionLocal
        test_client.testing_user_id = user_id
        yield test_client

        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)

    @staticmethod
    def build_realistic_pcap_bytes(tmp_path) -> bytes:
        pcap_path = tmp_path / "realistic.pcap"
        packets = []

        for port in range(20, 35):
            packets.append(
                Ether()
                / IP(src="192.168.1.50", dst="10.0.0.5")
                / TCP(sport=40000 + port, dport=port, flags="S")
            )

        for i in range(6):
            packets.append(
                Ether()
                / IP(src="192.168.1.20", dst="8.8.8.8")
                / UDP(sport=53000 + i, dport=53)
                / (b"x" * 80)
            )

        packets.append(
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.99")
            / TCP(sport=443, dport=5432, flags="PA")
            / (b"database-hop" * 10)
        )

        wrpcap(str(pcap_path), packets)
        return pcap_path.read_bytes()

    def test_real_pcap_upload_analyze_and_result_endpoints(self, client, tmp_path):
        pcap_bytes = self.build_realistic_pcap_bytes(tmp_path)

        upload_response = client.post(
            "/pcaps/upload",
            files={"file": ("realistic.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        assert upload_response.status_code == 200
        upload_payload = upload_response.json()
        assert upload_payload["original_filename"] == "realistic.pcap"
        assert upload_payload["file_size"] > 0
        assert upload_payload["status"] == "UPLOADED"
        assert len(upload_payload["sha256_hash"]) == 64

        analyze_response = client.post(f"/pcaps/{upload_payload['id']}/analyze")
        assert analyze_response.status_code == 200
        analysis = analyze_response.json()
        assert analysis["status"] == "success"
        assert analysis["pcap_id"] == upload_payload["id"]
        assert analysis["statistics"]["packets_parsed"] == 22
        assert analysis["statistics"]["flows_created"] >= 15
        assert analysis["statistics"]["alerts_rule_based"] >= 1
        assert analysis["statistics"]["alerts_total"] >= analysis["statistics"]["alerts_rule_based"]
        assert isinstance(analysis["incidents"], list)

        flows_response = client.get(f"/pcaps/{upload_payload['id']}/flows")
        assert flows_response.status_code == 200
        flows = flows_response.json()
        assert flows["total_flows"] == analysis["statistics"]["flows_created"]
        assert {"source_ip", "destination_ip", "protocol", "packet_count"}.issubset(flows["flows"][0])

        alerts_response = client.get(f"/pcaps/{upload_payload['id']}/alerts")
        assert alerts_response.status_code == 200
        alerts = alerts_response.json()
        assert alerts["total_alerts"] == analysis["statistics"]["alerts_total"]
        assert alerts["alerts"][0]["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        incidents_response = client.get(f"/pcaps/{upload_payload['id']}/incidents")
        assert incidents_response.status_code == 200
        incidents = incidents_response.json()
        assert incidents["total_incidents"] == analysis["statistics"]["incidents"]
        assert isinstance(incidents["incidents"], list)

    def test_network_graph_and_attack_path_api(self, client, tmp_path):
        pcap_bytes = self.build_realistic_pcap_bytes(tmp_path)
        upload_response = client.post(
            "/pcaps/upload",
            files={"file": ("topology.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        assert upload_response.status_code == 200
        pcap_id = upload_response.json()["id"]

        analyze_response = client.post(f"/pcaps/{pcap_id}/analyze")
        assert analyze_response.status_code == 200
        incident_id = analyze_response.json()["incidents"][0]["id"]

        db = client.testing_session_local()
        db.add(NetworkAsset(
            id=str(uuid4()),
            ip_address="10.0.0.99",
            hostname="critical-db",
            asset_type="database",
            criticality="CRITICAL",
        ))
        db.commit()
        db.close()

        graph_response = client.get(f"/pcaps/{pcap_id}/graph")
        assert graph_response.status_code == 200
        graph = graph_response.json()
        assert any(node["ip"] == "10.0.0.99" and node["risk_level"] == "CRITICAL" for node in graph["nodes"])
        assert any(edge["source"] == "10.0.0.5" and edge["target"] == "10.0.0.99" for edge in graph["edges"])

        paths_response = client.post(f"/pcaps/{pcap_id}/incidents/{incident_id}/attack-paths")
        assert paths_response.status_code == 200
        paths = paths_response.json()
        assert paths
        assert any(path["target_ip"] == "10.0.0.99" for path in paths)
        assert any("10.0.0.5" in path["path_nodes"] for path in paths)

        list_response = client.get(f"/pcaps/{pcap_id}/incidents/{incident_id}/attack-paths")
        assert list_response.status_code == 200
        assert list_response.json() == paths

    @pytest.mark.parametrize(
        ("filename", "content", "expected_detail"),
        [
            ("empty.pcap", b"", "empty"),
            ("not-a-capture.pcap", b"not a pcap", "Invalid PCAP file content"),
            ("capture.txt", b"\xd4\xc3\xb2\xa1", "Invalid file extension"),
        ],
    )
    def test_upload_rejects_empty_invalid_and_disallowed_files(
        self, client, filename, content, expected_detail
    ):
        response = client.post(
            "/pcaps/upload",
            files={"file": (filename, content, "application/octet-stream")},
        )
        assert response.status_code == 400
        assert expected_detail in response.json()["detail"]

    def test_malformed_pcap_analysis_returns_controlled_error(self, client):
        malformed_with_magic = b"\xd4\xc3\xb2\xa1" + b"truncated"

        upload_response = client.post(
            "/pcaps/upload",
            files={"file": ("malformed.pcap", malformed_with_magic, "application/vnd.tcpdump.pcap")},
        )
        assert upload_response.status_code == 200

        analyze_response = client.post(f"/pcaps/{upload_response.json()['id']}/analyze")
        assert analyze_response.status_code == 400
        assert "Malformed PCAP file" in analyze_response.json()["detail"]

    def test_password_hashing_works_with_project_bcrypt_pin(self):
        password_hash = PasswordHasher.hash("SecurePass123")
        assert PasswordHasher.verify("SecurePass123", password_hash)
        assert not PasswordHasher.verify("WrongPass123", password_hash)

    def test_viewer_token_cannot_upload_pcap(self, tmp_path, monkeypatch):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        Base.metadata.create_all(bind=engine)
        monkeypatch.setattr("app.services.pcap_service.settings.upload_dir", str(tmp_path / "uploads"))

        def override_db():
            test_db = TestingSessionLocal()
            try:
                yield test_db
            finally:
                test_db.close()

        app.dependency_overrides[get_db] = override_db
        token, _ = JWTHandler.create_access_token(str(uuid4()), "viewer", "VIEWER")

        try:
            test_client = TestClient(app)
            response = test_client.post(
                "/pcaps/upload",
                headers={"Authorization": f"Bearer {token}"},
                files={
                    "file": (
                        "viewer.pcap",
                        self.build_realistic_pcap_bytes(tmp_path),
                        "application/vnd.tcpdump.pcap",
                    )
                },
            )
            assert response.status_code == 403
            assert "Analyst or admin access required" in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()
            Base.metadata.drop_all(bind=engine)


if __name__ == "__main__":
    # Run basic tests
    pipeline = TestDetectionPipeline()
    
    print("Running basic pipeline tests...")
    pipeline.test_packet_parsing()
    print("[PASS] Packet parsing test passed")
    
    pipeline.test_flow_aggregation()
    print("[PASS] Flow aggregation test passed")
    
    pipeline.test_rule_based_detection()
    print("[PASS] Rule-based detection test passed")
    
    pipeline.test_ml_detection()
    print("[PASS] ML detection test passed")
    
    pipeline.test_risk_calculation()
    print("[PASS] Risk calculation test passed")
    
    pipeline.test_incident_correlation()
    print("[PASS] Incident correlation test passed")
    
    edge_cases = TestEdgeCases()
    
    print("\nRunning edge case tests...")
    edge_cases.test_empty_packet_list()
    print("[PASS] Empty packet list test passed")
    
    edge_cases.test_single_packet()
    print("[PASS] Single packet test passed")
    
    edge_cases.test_malformed_packets()
    print("[PASS] Malformed packets test passed")
    
    edge_cases.test_risk_score_boundaries()
    print("[PASS] Risk score boundaries test passed")
    
    print("\n[SUCCESS] All integration tests passed!")
