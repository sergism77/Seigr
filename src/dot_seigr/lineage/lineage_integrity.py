import logging
from datetime import datetime, timezone
from typing import List

logger = logging.getLogger(__name__)

class LineageIntegrity:
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
            logger.info("Integrity verified.")
        else:
            logger.warning(f"Integrity check failed. Expected {reference_hash}, got {current_hash}")
        return integrity_verified

    @staticmethod
    def verify_full_lineage_integrity(entries: List[dict], initial_hash: str) -> bool:
        """
        Verifies the integrity of an entire lineage by ensuring continuity of hashes across entries.

        Args:
            entries (List[dict]): A list of lineage entries as dictionaries, each containing 'previous_hashes' and 'calculated_hash'.
            initial_hash (str): The initial reference hash to start the verification chain.

        Returns:
            bool: True if the full lineage maintains hash continuity, False otherwise.
        """
        current_reference_hash = initial_hash

        for i, entry in enumerate(entries):
            calculated_hash = entry.get("calculated_hash")
            previous_hashes = entry.get("previous_hashes", [])
            
            # Verify current entry's hash continuity
            if current_reference_hash not in previous_hashes:
                logger.error(f"Hash continuity error at entry {i}. Expected one of {previous_hashes}, got {current_reference_hash}")
                return False

            # Check if calculated hash is valid and update reference hash for next entry
            if not LineageIntegrity.verify_integrity(calculated_hash, current_reference_hash):
                logger.error(f"Integrity verification failed at entry {i}")
                return False

            current_reference_hash = calculated_hash  # Move to the next in the chain
        
        logger.info("Full lineage integrity verified successfully.")
        return True

    @staticmethod
    def ping_activity() -> str:
        """
        Records a timestamped activity ping for tracking purposes.

        Returns:
            str: The UTC ISO-formatted timestamp of the ping.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info(f"Ping recorded at {timestamp}")
        return timestamp
