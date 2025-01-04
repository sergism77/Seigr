# src/immune_system/threat_response.py

import logging
from datetime import datetime, timezone

from src.replication.replication_controller import ReplicationController
from src.seigr_protocol.compiled.common_pb2 import ThreatDetectionLog, ThreatLevel

logger = logging.getLogger(__name__)


class ThreatResponseManager:
    """
    Centralized threat response manager for handling detected threats,
    executing response strategies, and escalating critical events.
    """

    def __init__(self, replication_controller: ReplicationController):
        """
        Initializes the Threat Response Manager.

        Args:
            replication_controller (ReplicationController): Handles replication logic.
        """
        self.replication_controller = replication_controller

    def handle_threat(self, segment_metadata, data: bytes):
        """
        Handles a detected threat on a segment.

        Args:
            segment_metadata: Metadata of the threatened segment.
            data (bytes): Segment data.
        """
        logger.warning(
            f"Handling threat for segment {segment_metadata.segment_hash}"
        )
        self._log_threat(
            segment_metadata,
            "Threat detected and mitigation initiated",
            ThreatLevel.THREAT_LEVEL_HIGH,
        )
        # Initiate necessary replication or rollback
        self.replication_controller.trigger_replication(segment_metadata.segment_hash)

    def handle_escalation(self, segment_hash: str):
        """
        Escalates threat response for critical segments.

        Args:
            segment_hash (str): Segment hash.
        """
        logger.critical(f"Escalating threat response for segment {segment_hash}")
        self.replication_controller.trigger_critical_replication(segment_hash)

    def _log_threat(
        self, segment_metadata, description: str, threat_level: ThreatLevel
    ):
        """
        Logs a threat event in a standardized way.

        Args:
            segment_metadata: Segment metadata.
            description (str): Description of the threat.
            threat_level (ThreatLevel): Threat severity.
        """
        detection_time = datetime.now(timezone.utc).isoformat()
        threat_log = ThreatDetectionLog(
            threat_level=threat_level,
            origin="ThreatResponseManager",
            description=description,
            detection_time={"created_at": detection_time},
            metadata={"segment_hash": segment_metadata.segment_hash},
            response_action="Replication Triggered",
            mitigated=True,
            impact_scope="local",
            escalation_policy_id="default_policy",
        )
        logger.warning(f"Threat Log Entry: {threat_log}")
