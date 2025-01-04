# src/crypto/threat_detection.py

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.hash_utils import generate_hash
from src.immune_system.threat_response import ThreatResponseManager  # Adjusted Import
from src.seigr_protocol.compiled.common_pb2 import (
    StandardResponse,
    ThreatDetectionLog,
    ThreatLevel,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)

logger = logging.getLogger(__name__)


### 🛡️ Threat Detection Engine ###


class ThreatDetectionEngine:
    """
    Core engine for threat detection in Seigr's ecosystem.
    Analyzes patterns, hashes, and behaviors to identify threats.
    """

    def __init__(self, response_manager: ThreatResponseManager = None):
        """
        Initializes the ThreatDetectionEngine.

        Args:
            response_manager (ThreatResponseManager): Instance from immune_system.
        """
        self.response_manager = response_manager or ThreatResponseManager()
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} ThreatDetectionEngine initialized.")

    def detect_signature_threat(
        self, data: bytes, known_threat_signatures: List[str]
    ) -> ThreatDetectionLog:
        """
        Detects threats based on known hash signatures.
        """
        try:
            data_hash = generate_hash(data)
            if data_hash in known_threat_signatures:
                threat_event = self._create_threat_log(
                    origin="SignatureDetection",
                    threat_level=ThreatLevel.THREAT_LEVEL_HIGH,
                    description="Known threat signature detected.",
                    metadata={"hash": data_hash},
                    mitigated=False,
                )
                logger.warning(
                    f"{SEIGR_CELL_ID_PREFIX} Threat detected via signature analysis: {data_hash}"
                )
                self.response_manager.handle_threat(threat_event)
                return threat_event
            logger.info(f"{SEIGR_CELL_ID_PREFIX} No signature threat detected.")
            return None
        except Exception as e:
            self._log_error(
                "signature_threat_detection_fail", "Failed to detect signature threat", e
            )
            raise ValueError("Signature threat detection failed.") from e

    def detect_anomalous_behavior(self, data_patterns: Dict[str, Any]) -> ThreatDetectionLog:
        """
        Detects threats based on anomalous behavior patterns.
        """
        try:
            anomaly_score = sum(data_patterns.get("scores", []))
            threshold = data_patterns.get("threshold", 50)
            if anomaly_score > threshold:
                threat_event = self._create_threat_log(
                    origin="BehavioralAnalysis",
                    threat_level=ThreatLevel.THREAT_LEVEL_MODERATE,
                    description="Anomalous behavior detected.",
                    metadata={"anomaly_score": anomaly_score, "threshold": threshold},
                    mitigated=False,
                )
                logger.warning(
                    f"{SEIGR_CELL_ID_PREFIX} Anomaly detected with score {anomaly_score}"
                )
                self.response_manager.handle_threat(threat_event)
                return threat_event
            logger.info(f"{SEIGR_CELL_ID_PREFIX} No anomaly detected.")
            return None
        except Exception as e:
            self._log_error("anomalous_behavior_detection_fail", "Failed to detect anomaly", e)
            raise ValueError("Anomalous behavior detection failed.") from e

    def _create_threat_log(
        self,
        origin: str,
        threat_level: ThreatLevel,
        description: str,
        metadata: Dict[str, Any],
        mitigated: bool = False,
    ) -> ThreatDetectionLog:
        """
        Creates a ThreatDetectionLog protobuf message.
        """
        detection_time = datetime.now(timezone.utc).isoformat()
        return ThreatDetectionLog(
            threat_level=threat_level,
            origin=origin,
            description=description,
            detection_time={"created_at": detection_time},
            metadata=metadata,
            response_action="Logged and alerted",
            mitigated=mitigated,
            impact_scope="local",
            mitigation_strategy="Immediate Isolation",
            escalation_policy_id="default_policy",
        )

    def log_standard_response(
        self,
        status: str,
        message: str,
        threat_level: ThreatLevel = ThreatLevel.THREAT_LEVEL_UNDEFINED,
    ) -> StandardResponse:
        """
        Logs a standardized threat response.
        """
        response = StandardResponse(
            status=status,
            message=message,
            threat_level=threat_level,
            request_id=str(uuid.uuid4()),
            metadata={"component": "ThreatDetectionEngine"},
        )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Standard response logged: {response}")
        return response

    def _log_error(self, error_id: str, message: str, exception: Exception):
        """
        Logs an error using a structured protocol buffer entry.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Threat Detection",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_TERMINATE,
        )
        logger.error(f"{message}: {exception}")
