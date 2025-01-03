# src/immune_system/immune_system.py

import logging
from datetime import datetime, timezone
from typing import Dict, Any

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.hash_utils import generate_hash
from src.crypto.helpers import encode_to_senary
from src.immune_system.integrity_monitoring import immune_ping
from src.replication.replication_controller import ReplicationController
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import SegmentMetadata
from src.seigr_protocol.compiled.common_pb2 import ThreatLevel, ThreatDetectionLog
from src.immune_system.threat_response import ThreatResponseManager
from src.immune_system.adaptive_monitoring import AdaptiveMonitor
from src.immune_system.rollback_handling import rollback_segment

logger = logging.getLogger(__name__)


class ImmuneSystem:
    """
    Core immune system module to handle integrity checks, threat detection, 
    adaptive monitoring, and replication strategies.
    """

    def __init__(
        self,
        monitored_segments: Dict[str, SegmentMetadata],
        replication_controller: ReplicationController,
        critical_threshold: int = 10,
    ):
        """
        Initializes the Immune System.

        Args:
            monitored_segments (Dict[str, SegmentMetadata]): Segments to monitor.
            replication_controller (ReplicationController): Handles replication logic.
            critical_threshold (int): Threshold to trigger critical escalation.
        """
        self.monitored_segments = monitored_segments
        self.replication_controller = replication_controller
        self.threat_response_manager = ThreatResponseManager(replication_controller)
        self.adaptive_monitor = AdaptiveMonitor(
            replication_controller, self.threat_response_manager, critical_threshold
        )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Immune System initialized.")

    ### 🛡️ Rollback Handling ###
    def rollback_segment(self, seigr_file) -> bool:
        """
        Attempts to roll back a corrupted or threatened segment.

        Args:
            seigr_file (SeigrFile): The file segment to roll back.

        Returns:
            bool: Success or failure of the rollback.
        """
        try:
            result = rollback_segment(seigr_file)
            if result:
                logger.info(
                    f"{SEIGR_CELL_ID_PREFIX} Rollback succeeded for segment {seigr_file.hash}."
                )
            else:
                logger.warning(
                    f"{SEIGR_CELL_ID_PREFIX} Rollback failed for segment {seigr_file.hash}."
                )
            return result
        except Exception as e:
            logger.error(
                f"{SEIGR_CELL_ID_PREFIX} Rollback failed: {str(e)}"
            )
            return False

    ### 🔄 Integrity Ping ###
    def immune_ping(self, segment_metadata: SegmentMetadata, data: bytes) -> bool:
        """
        Performs an integrity check on a segment.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment.
            data (bytes): Actual data to verify integrity.

        Returns:
            bool: True if integrity is intact, False otherwise.
        """
        segment_hash = segment_metadata.segment_hash
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Performing integrity ping on {segment_hash}.")
        try:
            is_valid = immune_ping(segment_metadata, data)
            if not is_valid:
                logger.warning(
                    f"{SEIGR_CELL_ID_PREFIX} Integrity check failed for {segment_hash}."
                )
                self._log_threat(
                    segment_metadata,
                    "Integrity check failed.",
                    ThreatLevel.THREAT_LEVEL_HIGH,
                )
                self.threat_response_manager.handle_threat(segment_metadata, data)
            return is_valid
        except Exception as e:
            logger.error(
                f"{SEIGR_CELL_ID_PREFIX} Failed immune_ping for {segment_hash}: {e}"
            )
            return False

    ### 📊 Threat Response ###
    def handle_threat_response(self, segment_hash: str):
        """
        Responds to detected threats in a segment.

        Args:
            segment_hash (str): The hash of the threatened segment.
        """
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Handling threat response for {segment_hash}.")
        self.threat_response_manager.handle_escalation(segment_hash)

    ### 🚨 Adaptive Monitoring Cycle ###
    def run_adaptive_monitoring_cycle(self):
        """
        Executes a monitoring cycle across all monitored segments.
        """
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Starting adaptive monitoring cycle.")
        segments_status = {
            segment_hash: {"segment_metadata": metadata, "data": b""}
            for segment_hash, metadata in self.monitored_segments.items()
        }
        self.adaptive_monitor.run_monitoring_cycle(segments_status)

    ### 🚦 Escalation for Critical Segments ###
    def escalate_critical_segments(self):
        """
        Escalates critical segments that require immediate attention.
        """
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Escalating critical segments.")
        self.adaptive_monitor.escalate_critical_segments()

    ### 📝 Threat Logging ###
    def _log_threat(
        self,
        segment_metadata: SegmentMetadata,
        description: str,
        threat_level: ThreatLevel,
    ):
        """
        Logs threat information using the ThreatDetectionLog protocol.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the threatened segment.
            description (str): Description of the threat.
            threat_level (ThreatLevel): Level of the detected threat.
        """
        detection_time = datetime.now(timezone.utc).isoformat()
        threat_log = ThreatDetectionLog(
            threat_level=threat_level,
            origin="ImmuneSystem",
            description=description,
            detection_time={"created_at": detection_time},
            metadata={"segment_hash": segment_metadata.segment_hash},
            response_action="Monitored and escalated",
            mitigated=False,
            impact_scope="local",
            escalation_policy_id="default_policy",
        )
        logger.warning(
            f"{SEIGR_CELL_ID_PREFIX} Threat detected: {threat_log}"
        )
