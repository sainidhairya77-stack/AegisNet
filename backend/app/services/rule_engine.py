"""
Rule-based network detection engine
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4
from sqlalchemy.orm import Session
from abc import ABC, abstractmethod
import logging

from app.models import NetworkFlow, Alert, AlertSeverity

logger = logging.getLogger(__name__)


class DetectionRule(ABC):
    """Base class for detection rules"""

    def __init__(self, rule_id: str, rule_name: str, severity: AlertSeverity):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity

    @abstractmethod
    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Execute detection rule on flows
        
        Returns:
            List of detection results
        """
        pass


class PortScanDetection(DetectionRule):
    """Detect port scanning activity"""

    def __init__(self):
        super().__init__(
            rule_id="port_scan_001",
            rule_name="Port Scan Detection",
            severity=AlertSeverity.MEDIUM
        )

    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Detect port scans:
        - Same source to many destination ports
        - Within short time window
        """
        alerts = []

        # Group flows by source IP
        flows_by_source = {}
        for flow in flows:
            if flow.source_ip not in flows_by_source:
                flows_by_source[flow.source_ip] = []
            flows_by_source[flow.source_ip].append(flow)

        # Check each source
        for source_ip, source_flows in flows_by_source.items():
            # Group by destination IP
            flows_by_dest = {}
            for flow in source_flows:
                if flow.destination_ip not in flows_by_dest:
                    flows_by_dest[flow.destination_ip] = []
                flows_by_dest[flow.destination_ip].append(flow)

            # Check for high port diversity to same destination
            for dest_ip, dest_flows in flows_by_dest.items():
                unique_ports = set(f.destination_port for f in dest_flows if f.destination_port)

                # Threshold: more than 10 unique ports
                if len(unique_ports) > 10:
                    time_diff = (dest_flows[-1].last_seen - dest_flows[0].first_seen).total_seconds()

                    alert = {
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                        "unique_ports_count": len(unique_ports),
                        "ports": sorted(unique_ports),
                        "time_window_seconds": time_diff,
                        "description": f"Potential port scan: {source_ip} contacted {dest_ip} on {len(unique_ports)} different ports",
                        "confidence": min(0.95, 0.5 + len(unique_ports) * 0.05),
                        "severity": self.severity,
                        "evidence": {
                            "rule": self.rule_name,
                            "unique_destinations_ports": len(unique_ports),
                            "destination_ip": dest_ip
                        }
                    }

                    alerts.append(alert)
                    logger.info(f"Port scan detected: {source_ip} -> {dest_ip} ({len(unique_ports)} ports)")

        return alerts


class HighConnectionRateDetection(DetectionRule):
    """Detect unusually high connection rates"""

    def __init__(self):
        super().__init__(
            rule_id="high_conn_rate_001",
            rule_name="High Connection Rate Detection",
            severity=AlertSeverity.MEDIUM
        )

    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Detect high connection rates:
        - Many flows from single source
        - Within short time
        """
        alerts = []

        # Group flows by source IP
        flows_by_source = {}
        for flow in flows:
            if flow.source_ip not in flows_by_source:
                flows_by_source[flow.source_ip] = []
            flows_by_source[flow.source_ip].append(flow)

        # Check each source
        for source_ip, source_flows in flows_by_source.items():
            if len(source_flows) > 50:  # Threshold: >50 flows
                # Calculate time window
                sorted_flows = sorted(source_flows, key=lambda f: f.first_seen)
                time_diff = (sorted_flows[-1].last_seen - sorted_flows[0].first_seen).total_seconds()

                if time_diff < 60:  # Within 60 seconds
                    conn_rate = len(source_flows) / max(time_diff, 1)

                    alert = {
                        "source_ip": source_ip,
                        "connection_count": len(source_flows),
                        "time_window_seconds": time_diff,
                        "connection_rate": conn_rate,
                        "description": f"High connection rate from {source_ip}: {conn_rate:.1f} connections/second",
                        "confidence": min(0.9, 0.6 + (conn_rate - 1) * 0.1),
                        "severity": self.severity,
                        "evidence": {
                            "rule": self.rule_name,
                            "flow_count": len(source_flows),
                            "rate_per_second": round(conn_rate, 2)
                        }
                    }

                    alerts.append(alert)
                    logger.info(f"High connection rate: {source_ip} ({conn_rate:.1f} conn/s)")

        return alerts


class FailedConnectionDetection(DetectionRule):
    """Detect repeated failed connection attempts"""

    def __init__(self):
        super().__init__(
            rule_id="failed_conn_001",
            rule_name="Failed Connection Detection",
            severity=AlertSeverity.MEDIUM
        )

    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Detect brute-force-like failed connections:
        - RST or SYN-only flows indicate failed connections
        - Many failures in short time
        """
        alerts = []

        # Look for flows with RST flags or failed handshakes
        failed_flows_by_source = {}

        for flow in flows:
            if flow.tcp_flags and ("R" in flow.tcp_flags or (flow.tcp_flags == "S")):  # RST or SYN-only
                key = (flow.source_ip, flow.destination_ip, flow.destination_port)

                if key not in failed_flows_by_source:
                    failed_flows_by_source[key] = []

                failed_flows_by_source[key].append(flow)

        # Check for suspicious patterns
        for (source_ip, dest_ip, dest_port), flows_with_failures in failed_flows_by_source.items():
            if len(flows_with_failures) > 10:  # Threshold: >10 failures
                time_diff = (flows_with_failures[-1].last_seen - flows_with_failures[0].first_seen).total_seconds()

                if time_diff < 300:  # Within 5 minutes
                    alert = {
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                        "destination_port": dest_port,
                        "failed_attempts": len(flows_with_failures),
                        "time_window_seconds": time_diff,
                        "description": f"Repeated failed connections from {source_ip} to {dest_ip}:{dest_port}",
                        "confidence": min(0.85, 0.5 + len(flows_with_failures) * 0.03),
                        "severity": AlertSeverity.MEDIUM,
                        "evidence": {
                            "rule": self.rule_name,
                            "failed_attempts": len(flows_with_failures),
                            "target": f"{dest_ip}:{dest_port}"
                        }
                    }

                    alerts.append(alert)
                    logger.info(f"Failed connections: {source_ip} -> {dest_ip}:{dest_port} ({len(flows_with_failures)} attempts)")

        return alerts


class SuspiciousOutboundDetection(DetectionRule):
    """Detect suspicious outbound traffic"""

    def __init__(self):
        super().__init__(
            rule_id="suspicious_outbound_001",
            rule_name="Suspicious Outbound Traffic",
            severity=AlertSeverity.HIGH
        )

    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Detect suspicious outbound patterns:
        - Large data transfers out
        - Unusual destination ports
        - C2-like communication patterns
        """
        alerts = []

        # Check for large outbound data transfers
        for flow in flows:
            # Assume internal networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if self._is_internal(flow.source_ip) and not self._is_internal(flow.destination_ip):
                # External destination
                if flow.byte_count > 1_000_000:  # >1MB outbound
                    alert = {
                        "source_ip": flow.source_ip,
                        "destination_ip": flow.destination_ip,
                        "bytes_transferred": flow.byte_count,
                        "destination_port": flow.destination_port,
                        "description": f"Large outbound data transfer from {flow.source_ip} to {flow.destination_ip}: {flow.byte_count / 1e6:.1f} MB",
                        "confidence": 0.75,
                        "severity": AlertSeverity.HIGH,
                        "evidence": {
                            "rule": self.rule_name,
                            "bytes_out": flow.byte_count,
                            "destination": f"{flow.destination_ip}:{flow.destination_port}"
                        }
                    }

                    alerts.append(alert)
                    logger.info(f"Suspicious outbound: {flow.source_ip} -> {flow.destination_ip} ({flow.byte_count / 1e6:.1f} MB)")

        return alerts

    @staticmethod
    def _is_internal(ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first_octet = int(parts[0])
            return first_octet in (10, 172, 192)
        except:
            return False


class RuleEngine:
    """Main rule-based detection engine"""

    def __init__(self):
        self.rules: List[DetectionRule] = [
            PortScanDetection(),
            HighConnectionRateDetection(),
            FailedConnectionDetection(),
            SuspiciousOutboundDetection(),
        ]

    def detect(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Run all detection rules on flows
        
        Returns:
            List of all detections
        """
        all_alerts = []

        for rule in self.rules:
            try:
                alerts = rule.detect(flows)
                all_alerts.extend(alerts)
                logger.debug(f"Rule {rule.rule_name} found {len(alerts)} alerts")
            except Exception as e:
                logger.error(f"Error in rule {rule.rule_name}: {str(e)}")

        logger.info(f"Rule engine detection complete: {len(all_alerts)} total alerts")
        return all_alerts

    def save_alerts(self, db: Session, pcap_id: str, alerts: List[Dict[str, Any]], source_type: str = "rule"):
        """Save detected alerts to database"""
        created_count = 0

        for alert_data in alerts:
            alert = Alert(
                id=str(uuid4()),
                pcap_file_id=pcap_id,
                rule_id=alert_data.get("evidence", {}).get("rule", "unknown"),
                rule_name=alert_data.get("evidence", {}).get("rule", "Unknown Rule"),
                severity=alert_data.get("severity", AlertSeverity.MEDIUM),
                confidence=alert_data.get("confidence", 0.5),
                source_ip=alert_data.get("source_ip"),
                destination_ip=alert_data.get("destination_ip"),
                source_port=alert_data.get("source_port"),
                destination_port=alert_data.get("destination_port"),
                protocol=alert_data.get("protocol"),
                alert_type=source_type,
                description=alert_data.get("description", ""),
                evidence=alert_data.get("evidence", {}),
                triggered_at=datetime.utcnow()
            )

            db.add(alert)
            created_count += 1

        db.commit()
        logger.info(f"Saved {created_count} rule-based alerts to database")
