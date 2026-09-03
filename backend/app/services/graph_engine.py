"""
Network topology and attack path analysis services.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

import networkx as nx
from sqlalchemy.orm import Session

from app.models import AttackPath, Incident, NetworkAsset, NetworkFlow
from app.utils.validators import IPValidator


class NetworkTopologyBuilder:
    """Build observed network topology from analyzed flows."""

    @staticmethod
    def build_graph(db: Session, pcap_id: str) -> Dict[str, List[Dict[str, Any]]]:
        flows = (
            db.query(NetworkFlow)
            .filter(NetworkFlow.pcap_file_id == pcap_id)
            .order_by(NetworkFlow.first_seen.asc())
            .all()
        )
        assets = {asset.ip_address: asset for asset in db.query(NetworkAsset).all()}
        alert_ips = NetworkTopologyBuilder._alert_ips_by_pcap(db, pcap_id)

        nodes_by_ip: Dict[str, Dict[str, Any]] = {}
        edges_by_pair: Dict[tuple[str, str], Dict[str, Any]] = {}

        for flow in flows:
            for ip in (flow.source_ip, flow.destination_ip):
                if ip not in nodes_by_ip:
                    nodes_by_ip[ip] = NetworkTopologyBuilder._build_node(ip, assets.get(ip), alert_ips)

            edge_key = (flow.source_ip, flow.destination_ip)
            if edge_key not in edges_by_pair:
                edges_by_pair[edge_key] = {
                    "source": flow.source_ip,
                    "target": flow.destination_ip,
                    "protocol": flow.protocol,
                    "ports": set(),
                    "connection_count": 0,
                    "suspicious": False,
                }

            edge = edges_by_pair[edge_key]
            edge["connection_count"] += 1
            if flow.destination_port:
                edge["ports"].add(flow.destination_port)
            if flow.source_ip in alert_ips or flow.destination_ip in alert_ips:
                edge["suspicious"] = True
            if flow.protocol not in edge["protocol"].split(","):
                edge["protocol"] = ",".join(sorted({*edge["protocol"].split(","), flow.protocol}))

        edges = []
        for edge in edges_by_pair.values():
            edges.append({
                **edge,
                "ports": sorted(edge["ports"]),
            })

        return {
            "nodes": sorted(nodes_by_ip.values(), key=lambda node: node["ip"]),
            "edges": sorted(edges, key=lambda edge: (edge["source"], edge["target"])),
        }

    @staticmethod
    def _build_node(ip: str, asset: Optional[NetworkAsset], alert_ips: set[str]) -> Dict[str, Any]:
        if asset:
            label = asset.hostname or asset.ip_address
            node_type = asset.asset_type or "asset"
            risk_level = asset.criticality or "MEDIUM"
        else:
            label = ip
            node_type = "internal" if IPValidator.is_private_ip(ip) else "external"
            risk_level = "MEDIUM" if ip in alert_ips else "LOW"

        if ip in alert_ips and risk_level == "LOW":
            risk_level = "MEDIUM"

        return {
            "id": ip,
            "ip": ip,
            "label": label,
            "type": node_type,
            "risk_level": risk_level,
        }

    @staticmethod
    def _alert_ips_by_pcap(db: Session, pcap_id: str) -> set[str]:
        from app.models import Alert

        ips = set()
        for alert in db.query(Alert).filter(Alert.pcap_file_id == pcap_id).all():
            if alert.source_ip:
                ips.add(alert.source_ip)
            if alert.destination_ip:
                ips.add(alert.destination_ip)
        return ips


class AttackPathAnalyzer:
    """Find and persist observed paths from incident sources to critical assets."""

    @staticmethod
    def analyze_incident(db: Session, incident: Incident) -> List[AttackPath]:
        existing_paths = AttackPathAnalyzer.list_for_incident(db, incident.id)
        if existing_paths:
            return existing_paths

        graph = AttackPathAnalyzer._build_nx_graph(db, incident.pcap_file_id)
        sources = [ip for ip in (incident.source_ips or []) if ip in graph]
        targets = AttackPathAnalyzer._target_ips(db, incident, graph)

        paths: List[AttackPath] = []
        seen = set()

        for source_ip in sources:
            for target_ip in targets:
                if source_ip == target_ip or (source_ip, target_ip) in seen:
                    continue
                seen.add((source_ip, target_ip))

                try:
                    path_nodes = nx.shortest_path(graph, source_ip, target_ip)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

                path_edges = AttackPathAnalyzer._path_edges(graph, path_nodes)
                risk_score = AttackPathAnalyzer._path_risk(db, incident, target_ip, len(path_nodes))

                attack_path = AttackPath(
                    id=str(uuid4()),
                    incident_id=incident.id,
                    source_ip=source_ip,
                    target_ip=target_ip,
                    path_nodes=path_nodes,
                    path_edges=path_edges,
                    risk_score=risk_score,
                    confidence=0.8 if len(path_nodes) <= 3 else 0.6,
                    description=(
                        f"Observed path from {source_ip} to {target_ip} "
                        f"through {len(path_nodes)} nodes"
                    ),
                    created_at=datetime.utcnow(),
                )
                db.add(attack_path)
                paths.append(attack_path)

        db.commit()

        return AttackPathAnalyzer.list_for_incident(db, incident.id)

    @staticmethod
    def list_for_incident(db: Session, incident_id: str) -> List[AttackPath]:
        return (
            db.query(AttackPath)
            .filter(AttackPath.incident_id == incident_id)
            .order_by(AttackPath.risk_score.desc())
            .all()
        )

    @staticmethod
    def _build_nx_graph(db: Session, pcap_id: str) -> nx.DiGraph:
        graph = nx.DiGraph()
        flows = db.query(NetworkFlow).filter(NetworkFlow.pcap_file_id == pcap_id).all()

        for flow in flows:
            if not graph.has_edge(flow.source_ip, flow.destination_ip):
                graph.add_edge(
                    flow.source_ip,
                    flow.destination_ip,
                    protocols=set(),
                    ports=set(),
                    connection_count=0,
                )
            edge = graph[flow.source_ip][flow.destination_ip]
            edge["protocols"].add(flow.protocol)
            if flow.destination_port:
                edge["ports"].add(flow.destination_port)
            edge["connection_count"] += 1

        return graph

    @staticmethod
    def _target_ips(db: Session, incident: Incident, graph: nx.DiGraph) -> List[str]:
        critical_assets = (
            db.query(NetworkAsset)
            .filter(NetworkAsset.criticality.in_(["CRITICAL", "HIGH"]))
            .all()
        )
        targets = [asset.ip_address for asset in critical_assets if asset.ip_address in graph]

        if not targets:
            targets = [ip for ip in (incident.destination_ips or []) if ip in graph]

        return sorted(set(targets))

    @staticmethod
    def _path_edges(graph: nx.DiGraph, path_nodes: List[str]) -> List[Dict[str, Any]]:
        edges = []
        for source, target in zip(path_nodes, path_nodes[1:]):
            edge = graph[source][target]
            edges.append({
                "source": source,
                "target": target,
                "protocols": sorted(edge["protocols"]),
                "ports": sorted(edge["ports"]),
                "connection_count": edge["connection_count"],
            })
        return edges

    @staticmethod
    def _path_risk(db: Session, incident: Incident, target_ip: str, node_count: int) -> float:
        asset = db.query(NetworkAsset).filter(NetworkAsset.ip_address == target_ip).first()
        criticality_bonus = {
            "CRITICAL": 20,
            "HIGH": 10,
            "MEDIUM": 5,
        }.get(asset.criticality if asset else None, 0)
        proximity_bonus = max(0, 10 - max(0, node_count - 2) * 2)
        return min(100, max(0, (incident.risk_score or 0) + criticality_bonus + proximity_bonus))
