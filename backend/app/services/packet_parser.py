"""
Network packet parsing and analysis using Scapy
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import uuid4
from sqlalchemy.orm import Session
from pathlib import Path
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw
import logging

from app.models import NetworkFlow, NetworkAsset
from app.utils.validators import IPValidator

logger = logging.getLogger(__name__)


class PcapParseError(ValueError):
    """Raised when a PCAP file cannot be parsed safely."""


class PacketParser:
    """Parse and analyze network packets from PCAP files"""

    PCAP_MAGIC_HEADERS = (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    )

    @staticmethod
    def parse_pcap_file(pcap_path: str) -> list[Dict[str, Any]]:
        """
        Parse PCAP file and extract packet information
        
        Returns:
            List of packet dictionaries with extracted features
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists() or not pcap_file.is_file():
            raise PcapParseError("PCAP file is not available")

        if pcap_file.stat().st_size == 0:
            raise PcapParseError("PCAP file is empty")

        with pcap_file.open("rb") as f:
            magic = f.read(4)

        if not any(magic == header for header in PacketParser.PCAP_MAGIC_HEADERS):
            raise PcapParseError("Invalid PCAP file content")

        packets = []
        
        try:
            pcap_data = rdpcap(pcap_path)
            logger.info(f"Loaded {len(pcap_data)} packets from {pcap_path}")

            for packet in pcap_data:
                packet_info = PacketParser._extract_packet_info(packet)
                if packet_info:
                    packets.append(packet_info)

            logger.info(f"Extracted {len(packets)} analyzable packets")
            return packets

        except PcapParseError:
            raise
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {str(e)}")
            raise PcapParseError("Malformed PCAP file") from e

    @staticmethod
    def _extract_packet_info(packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from a single packet"""
        try:
            info = {
                "timestamp": float(packet.time),
                "size": len(packet),
                "protocol": None,
                "source_ip": None,
                "destination_ip": None,
                "source_port": None,
                "destination_port": None,
                "tcp_flags": None,
                "has_payload": False
            }

            # Extract Layer 3 (IP)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info["source_ip"] = ip_layer.src
                info["destination_ip"] = ip_layer.dst
                info["ttl"] = ip_layer.ttl
                info["protocol"] = PacketParser._get_protocol_name(ip_layer.proto)

            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                info["source_ip"] = ipv6_layer.src
                info["destination_ip"] = ipv6_layer.dst
                info["protocol"] = ipv6_layer.nxt

            # Extract Layer 4 (TCP/UDP)
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                info["source_port"] = tcp_layer.sport
                info["destination_port"] = tcp_layer.dport
                info["tcp_flags"] = PacketParser._get_tcp_flags(tcp_layer.flags)
                info["protocol"] = "TCP"

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                info["source_port"] = udp_layer.sport
                info["destination_port"] = udp_layer.dport
                info["protocol"] = "UDP"

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                info["icmp_type"] = icmp_layer.type
                info["icmp_code"] = icmp_layer.code
                info["protocol"] = "ICMP"

            # Check for payload
            info["has_payload"] = packet.haslayer(Raw)

            # Only keep packets with IP information
            if info["source_ip"] and info["destination_ip"]:
                return info

        except Exception as e:
            logger.debug(f"Could not extract packet info: {str(e)}")

        return None

    @staticmethod
    def _get_protocol_name(proto_num: int) -> str:
        """Convert protocol number to name"""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            47: "GRE",
            50: "ESP",
            51: "AH",
        }
        return protocol_map.get(proto_num, f"Protocol_{proto_num}")

    @staticmethod
    def _get_tcp_flags(flags) -> str:
        """Convert TCP flags to string representation"""
        flag_names = []
        
        flag_map = {
            0x01: "F",  # FIN
            0x02: "S",  # SYN
            0x04: "R",  # RST
            0x08: "P",  # PSH
            0x10: "A",  # ACK
            0x20: "U",  # URG
            0x40: "E",  # ECE
            0x80: "C",  # CWR
        }

        if isinstance(flags, int):
            for bit, name in flag_map.items():
                if flags & bit:
                    flag_names.append(name)

        return "".join(flag_names) if flag_names else "NONE"


class FlowAggregator:
    """Aggregate packets into network flows"""

    # Flow timeout (seconds)
    FLOW_TIMEOUT = 300

    @staticmethod
    def create_flows(packets: list[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create network flows from packets
        
        A flow is defined as: src_ip, dst_ip, src_port, dst_port, protocol
        """
        flows = {}

        for packet in packets:
            # Skip packets without IP info
            if not packet.get("source_ip") or not packet.get("destination_ip"):
                continue
            
            # Skip packets without protocol
            if not packet.get("protocol"):
                continue

            # Create flow key with None defaults for missing ports
            flow_key = (
                packet["source_ip"],
                packet["destination_ip"],
                packet.get("source_port"),
                packet.get("destination_port"),
                packet["protocol"]
            )

            if flow_key not in flows:
                flows[flow_key] = {
                    "source_ip": packet["source_ip"],
                    "destination_ip": packet["destination_ip"],
                    "source_port": packet.get("source_port"),
                    "destination_port": packet.get("destination_port"),
                    "protocol": packet["protocol"],
                    "first_seen": datetime.fromtimestamp(packet.get("timestamp", 0)),
                    "last_seen": datetime.fromtimestamp(packet.get("timestamp", 0)),
                    "packet_count": 0,
                    "byte_count": 0,
                    "tcp_flags": set(),
                    "has_retransmissions": False,
                    "has_failed_connections": False,
                    "packets": []
                }

            flow = flows[flow_key]
            flow["packet_count"] += 1
            flow["byte_count"] += packet.get("size", 0)
            flow["last_seen"] = datetime.fromtimestamp(packet.get("timestamp", 0))

            if packet.get("tcp_flags"):
                flow["tcp_flags"].add(packet["tcp_flags"])

            flow["packets"].append(packet)

        # Convert to list and finalize
        flow_list = []
        for flow in flows.values():
            flow["tcp_flags"] = ",".join(sorted(flow["tcp_flags"]))
            flow["duration_seconds"] = (flow["last_seen"] - flow["first_seen"]).total_seconds()
            
            # Detect potential retransmissions (RST flags)
            if "R" in flow["tcp_flags"]:
                flow["has_retransmissions"] = True

            flow_list.append(flow)

        logger.info(f"Created {len(flow_list)} network flows from {len(packets)} packets")
        return flow_list

    @staticmethod
    def save_flows(db: Session, pcap_id: str, flows: List[Dict[str, Any]]):
        """Save network flows to database"""
        created_count = 0

        for flow_data in flows:
            network_flow = NetworkFlow(
                id=str(uuid4()),
                pcap_file_id=pcap_id,
                source_ip=flow_data["source_ip"],
                destination_ip=flow_data["destination_ip"],
                source_port=flow_data["source_port"],
                destination_port=flow_data["destination_port"],
                protocol=flow_data["protocol"],
                first_seen=flow_data["first_seen"],
                last_seen=flow_data["last_seen"],
                duration_seconds=flow_data["duration_seconds"],
                packet_count=flow_data["packet_count"],
                byte_count=flow_data["byte_count"],
                tcp_flags=flow_data["tcp_flags"],
                has_retransmissions=flow_data["has_retransmissions"],
                has_failed_connections=flow_data["has_failed_connections"]
            )

            db.add(network_flow)
            created_count += 1

        db.commit()
        logger.info(f"Saved {created_count} network flows to database")

    @staticmethod
    def get_flows_for_pcap(db: Session, pcap_id: str) -> list[NetworkFlow]:
        """Retrieve all flows for a PCAP file"""
        return db.query(NetworkFlow).filter(NetworkFlow.pcap_file_id == pcap_id).all()


class FeatureExtractor:
    """Extract features from network flows for detection"""

    @staticmethod
    def extract_features(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract statistical features from flows
        
        Returns:
            Dictionary of computed features
        """
        if not flows:
            return {}

        features = {
            "total_flows": len(flows),
            "total_packets": sum(f["packet_count"] for f in flows),
            "total_bytes": sum(f["byte_count"] for f in flows),
            "unique_source_ips": len(set(f["source_ip"] for f in flows)),
            "unique_dest_ips": len(set(f["destination_ip"] for f in flows)),
            "unique_source_ports": len(set(f["source_port"] for f in flows if f["source_port"])),
            "unique_dest_ports": len(set(f["destination_port"] for f in flows if f["destination_port"])),
            "protocol_distribution": {},
            "avg_packets_per_flow": 0,
            "avg_bytes_per_flow": 0,
            "avg_flow_duration": 0,
            "connection_rate": 0,
            "protocols": set()
        }

        # Protocol distribution
        for flow in flows:
            proto = flow["protocol"]
            features["protocol_distribution"][proto] = features["protocol_distribution"].get(proto, 0) + 1
            features["protocols"].add(proto)

        # Averages
        if flows:
            features["avg_packets_per_flow"] = features["total_packets"] / len(flows)
            features["avg_bytes_per_flow"] = features["total_bytes"] / len(flows)
            features["avg_flow_duration"] = sum(f["duration_seconds"] for f in flows) / len(flows)

        features["protocols"] = list(features["protocols"])

        return features
