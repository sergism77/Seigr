import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class LineageIntegrity:
    @staticmethod
    def verify_integrity(current_hash: str, reference_hash: str) -> bool:
        integrity_verified = current_hash == reference_hash
        if integrity_verified:
            logger.info("Integrity verified.")
        else:
            logger.warning(f"Integrity check failed. Expected {reference_hash}, got {current_hash}")
        return integrity_verified

    @staticmethod
    def ping_activity() -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info(f"Ping recorded at {timestamp}")
        return timestamp
