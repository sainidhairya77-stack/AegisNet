"""
Machine Learning anomaly detection engine using Isolation Forest
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from uuid import uuid4
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session
import logging
import json
from pathlib import Path

from app.config import get_settings
from app.models import NetworkFlow, Alert, AlertSeverity

logger = logging.getLogger(__name__)
settings = get_settings()


class FeatureVectorizer:
    """Convert network flows to feature vectors for ML"""

    # Features to extract
    FEATURES = [
        "packet_count",
        "byte_count",
        "duration_seconds",
        "source_port",
        "destination_port",
        "unique_dest_ports_per_src",
        "avg_packet_size",
        "flow_rate"
    ]

    @staticmethod
    def flows_to_dataframe(flows: List[NetworkFlow]) -> Tuple[pd.DataFrame, List[str]]:
        """
        Convert network flows to feature DataFrame
        
        Returns:
            Tuple of (dataframe, flow_ids)
        """
        flow_data = []
        flow_ids = []

        # Group by source IP to calculate some aggregate features
        flows_by_src = {}
        for flow in flows:
            if flow.source_ip not in flows_by_src:
                flows_by_src[flow.source_ip] = []
            flows_by_src[flow.source_ip].append(flow)

        for flow in flows:
            # Basic features
            packet_count = flow.packet_count or 0
            byte_count = flow.byte_count or 0
            duration = flow.duration_seconds or 0.1  # Avoid division by zero
            src_port = flow.source_port or 0
            dst_port = flow.destination_port or 0

            # Calculate features
            avg_packet_size = byte_count / max(packet_count, 1)
            flow_rate = packet_count / max(duration, 1)
            unique_dst_ports = len(set(f.destination_port for f in flows_by_src[flow.source_ip]))

            features = {
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration_seconds": duration,
                "source_port": src_port,
                "destination_port": dst_port,
                "unique_dest_ports_per_src": unique_dst_ports,
                "avg_packet_size": avg_packet_size,
                "flow_rate": flow_rate
            }

            flow_data.append(features)
            flow_ids.append(flow.id)

        if not flow_data:
            return pd.DataFrame(), []

        df = pd.DataFrame(flow_data)

        # Handle any NaN values
        df = df.fillna(0)

        return df, flow_ids

    @staticmethod
    def preprocess_features(X: np.ndarray) -> Tuple[np.ndarray, StandardScaler]:
        """
        Normalize features for ML model
        
        Returns:
            Tuple of (normalized_features, scaler)
        """
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        return X_scaled, scaler


class AnomalyDetector:
    """Isolation Forest-based anomaly detection"""

    def __init__(self, contamination: float = 0.1):
        """
        Initialize Isolation Forest
        
        Args:
            contamination: Expected proportion of anomalies (0.0-1.0)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto'
        )
        self.scaler = None

    def fit(self, X: np.ndarray):
        """Train the model on normal data"""
        self.model.fit(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies (-1 for anomaly, 1 for normal)
        
        Returns:
            Array of predictions
        """
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for samples
        
        Returns:
            Array of anomaly scores (lower = more anomalous)
        """
        return self.model.score_samples(X)

    def normalize_anomaly_score(self, raw_score: float) -> float:
        """
        Normalize anomaly score to 0-100 scale
        Higher score = more anomalous
        
        -1.0 (most anomalous) -> 100
         0.0 (neutral)        -> 50
         1.0 (least anomalous) -> 0
        """
        # raw_score is typically in range [-1, 1]
        # normalize to 0-1 first, then scale to 0-100
        normalized = (1 - raw_score) / 2.0
        return min(100, max(0, normalized * 100))


class MLDetectionEngine:
    """Machine Learning based detection engine"""

    def __init__(self):
        self.detector = AnomalyDetector(contamination=0.15)
        self.model_path = Path(settings.demo_data_dir) / "anomaly_model.pkl"
        self.scaler_path = Path(settings.demo_data_dir) / "scaler.pkl"

    def detect(self, flows: List[NetworkFlow], threshold: float = 70) -> List[Dict[str, Any]]:
        """
        Detect anomalies in network flows
        
        Args:
            flows: List of network flows
            threshold: Anomaly score threshold (0-100) for alerting
        
        Returns:
            List of anomalous flows
        """
        if not flows or len(flows) < 5:
            logger.warning("Insufficient flows for ML detection")
            return []

        # Convert to DataFrame
        df, flow_ids = FeatureVectorizer.flows_to_dataframe(flows)

        if df.empty:
            return []

        # Get features
        X = df[FeatureVectorizer.FEATURES].values

        # Normalize features
        X_scaled, scaler = FeatureVectorizer.preprocess_features(X)

        # Fit the model on the current data if not already fitted
        # (In production, this would use pre-trained models)
        self.detector.model.fit(X_scaled)

        # Get predictions
        predictions = self.detector.predict(X_scaled)
        raw_scores = self.detector.score_samples(X_scaled)

        # Convert raw scores to 0-100 scale
        anomaly_scores = [self.detector.normalize_anomaly_score(s) for s in raw_scores]

        # Create alerts for anomalies
        alerts = []

        for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if score >= threshold:  # Anomalous
                flow = flows[i]

                alert = {
                    "flow_id": flow_ids[i],
                    "source_ip": flow.source_ip,
                    "destination_ip": flow.destination_ip,
                    "source_port": flow.source_port,
                    "destination_port": flow.destination_port,
                    "protocol": flow.protocol,
                    "anomaly_score": round(score, 2),
                    "description": f"Anomalous network flow detected: {flow.source_ip} -> {flow.destination_ip}",
                    "confidence": min(0.95, (score / 100) * 0.95),
                    "severity": self._score_to_severity(score),
                    "evidence": {
                        "rule": "ML Anomaly Detection",
                        "anomaly_score": round(score, 2),
                        "model": "Isolation Forest",
                        "features": {
                            "packet_count": flow.packet_count,
                            "byte_count": flow.byte_count,
                            "duration_seconds": flow.duration_seconds,
                            "flow_rate": flow.packet_count / max(flow.duration_seconds, 1)
                        }
                    }
                }

                alerts.append(alert)
                logger.info(f"ML anomaly detected: {flow.source_ip} -> {flow.destination_ip} (score: {score:.1f})")

        return alerts

    @staticmethod
    def _score_to_severity(score: float) -> AlertSeverity:
        """Convert anomaly score to severity"""
        if score >= 85:
            return AlertSeverity.CRITICAL
        elif score >= 75:
            return AlertSeverity.HIGH
        elif score >= 60:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def save_alerts(self, db: Session, pcap_id: str, alerts: List[Dict[str, Any]]):
        """Save ML-detected alerts to database"""
        created_count = 0

        for alert_data in alerts:
            alert = Alert(
                id=str(uuid4()),
                pcap_file_id=pcap_id,
                rule_id="ml_anomaly_001",
                rule_name="ML Anomaly Detection",
                severity=alert_data.get("severity", AlertSeverity.MEDIUM),
                confidence=alert_data.get("confidence", 0.5),
                source_ip=alert_data.get("source_ip"),
                destination_ip=alert_data.get("destination_ip"),
                source_port=alert_data.get("source_port"),
                destination_port=alert_data.get("destination_port"),
                protocol=alert_data.get("protocol"),
                alert_type="ml_anomaly",
                description=alert_data.get("description", ""),
                evidence=alert_data.get("evidence", {}),
                triggered_at=datetime.utcnow()
            )

            db.add(alert)
            created_count += 1

        db.commit()
        logger.info(f"Saved {created_count} ML-based alerts to database")
