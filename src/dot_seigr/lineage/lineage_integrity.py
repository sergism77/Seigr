from typing import Dict, List
from datetime import datetime, timezone

from google.protobuf.timestamp_pb2 import Timestamp
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.lineage_pb2 import LineageEntry
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


class LineageIntegrity:
    """
    Provides methods to verify the integrity of lineage entries by checking hash continuity
    and ensuring each entry aligns with the expected reference hashes.
    """

    @staticmethod
    def verify_full_lineage_integrity(entries: List[LineageEntry], initial_hash: str) -> bool:
        """
        Verifies the integrity of an entire lineage by ensuring continuity of hashes across entries.

        Args:
            entries (List[LineageEntry]): List of LineageEntry protobuf messages.
            initial_hash (str): The initial reference hash to start the verification chain.

        Returns:
            bool: True if the full lineage maintains hash continuity, False otherwise.
        """
        current_reference_hash = initial_hash
        all_entries_valid = True

        for i, entry in enumerate(entries):
            calculated_hash = entry.calculated_hash
            previous_hashes = entry.previous_hashes

            if not calculated_hash:
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                    category="LineageIntegrity",
                    message=f"❌ Entry {i} is missing 'calculated_hash'. Verification failed.",
                )
                return False

            # Ensure current reference hash exists in previous hashes
            if current_reference_hash not in previous_hashes:
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                    category="LineageIntegrity",
                    message=f"❌ Hash continuity error at entry {i}. Expected one of {previous_hashes}, got {current_reference_hash}",
                )
                all_entries_valid = False
                continue

            # Verify integrity of the current entry
            if not LineageIntegrity.verify_integrity(calculated_hash, current_reference_hash):
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                    category="LineageIntegrity",
                    message=f"❌ Integrity verification failed at entry {i}",
                )
                all_entries_valid = False
                continue

            # Update reference hash for the next iteration
            current_reference_hash = calculated_hash

        if all_entries_valid:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="LineageIntegrity",
                message="✅ Full lineage integrity verified successfully.",
            )
        else:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="LineageIntegrity",
                message="⚠️ One or more lineage entries failed integrity verification.",
            )

        return all_entries_valid

    @staticmethod
    def ping_activity() -> Timestamp:
        """
        Records a timestamped activity ping for tracking purposes.

        Returns:
            Timestamp: The Protobuf Timestamp of the recorded ping.
        """
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="LineageIntegrity",
            message=f"🔵 Ping recorded at {timestamp_proto.ToJsonString()}",
        )

        return timestamp_proto
