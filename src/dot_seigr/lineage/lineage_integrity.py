import logging
from typing import Dict, List
from datetime import datetime, timezone

from google.protobuf.timestamp_pb2 import Timestamp
from src.logger.secure_logger import secure_logger

class LineageIntegrity:
    """
    Provides methods to verify the integrity of lineage entries by checking hash continuity
    and ensuring each entry aligns with the expected reference hashes.
    """

    @staticmethod
    def verify_integrity(current_hash: str, reference_hash: str) -> bool:
        """
        Verifies the integrity of a lineage entry by comparing the current hash with a reference hash.

        Args:
            current_hash (str): The calculated hash of the current lineage entry.
            reference_hash (str): The expected reference hash for verification.

        Returns:
            bool: True if integrity is verified, False otherwise.
        """
        integrity_verified = current_hash == reference_hash

        if integrity_verified:
            secure_logger.log_audit_event(
                "info", "LineageIntegrity", f"✅ Integrity verified successfully for hash: {current_hash}"
            )
        else:
            secure_logger.log_audit_event(
                "warning",
                "LineageIntegrity",
                f"⚠️ Integrity check failed. Expected {reference_hash}, got {current_hash}",
            )

        return integrity_verified

    @staticmethod
    def verify_full_lineage_integrity(entries: List[Dict[str, any]], initial_hash: str) -> bool:
        """
        Verifies the integrity of an entire lineage by ensuring continuity of hashes across entries.

        Args:
            entries (List[Dict]): A list of lineage entries as dictionaries, each containing
                                  'previous_hashes' and 'calculated_hash'.
            initial_hash (str): The initial reference hash to start the verification chain.

        Returns:
            bool: True if the full lineage maintains hash continuity, False otherwise.
        """
        current_reference_hash = initial_hash
        all_entries_valid = True

        for i, entry in enumerate(entries):
            calculated_hash = entry.get("calculated_hash")
            previous_hashes = entry.get("previous_hashes", [])

            if not calculated_hash:
                secure_logger.log_audit_event(
                    "error",
                    "LineageIntegrity",
                    f"❌ Entry {i} is missing 'calculated_hash'. Verification failed.",
                )
                return False

            # Ensure current reference hash exists in previous hashes
            if current_reference_hash not in previous_hashes:
                secure_logger.log_audit_event(
                    "error",
                    "LineageIntegrity",
                    f"❌ Hash continuity error at entry {i}. Expected one of {previous_hashes}, got {current_reference_hash}",
                )
                all_entries_valid = False
                continue

            # Verify integrity of the current entry
            if not LineageIntegrity.verify_integrity(calculated_hash, current_reference_hash):
                secure_logger.log_audit_event(
                    "error",
                    "LineageIntegrity",
                    f"❌ Integrity verification failed at entry {i}",
                )
                all_entries_valid = False
                continue

            # Update reference hash for the next iteration
            current_reference_hash = calculated_hash

        if all_entries_valid:
            secure_logger.log_audit_event(
                "info", "LineageIntegrity", "✅ Full lineage integrity verified successfully."
            )
        else:
            secure_logger.log_audit_event(
                "warning", "LineageIntegrity", "⚠️ One or more lineage entries failed integrity verification."
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
            "info", "LineageIntegrity", f"🔵 Ping recorded at {timestamp_proto.ToJsonString()}"
        )

        return timestamp_proto
