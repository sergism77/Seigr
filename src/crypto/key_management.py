import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List
from src.crypto.key_derivation import generate_salt, derive_key_to_protocol
from src.seigr_protocol.compiled.encryption_pb2 import SymmetricKey, KeyStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

# Initialize the logger
logger = logging.getLogger(__name__)

class KeyManager:
    def __init__(self):
        self.keys: Dict[str, SymmetricKey] = {}  # Store keys by key_id for easy retrieval

    def generate_key(self, password: Optional[str] = None, use_senary: bool = True) -> SymmetricKey:
        """
        Generates a new cryptographic key and stores it in memory.
        """
        salt = generate_salt()
        key = derive_key_to_protocol(password, salt=salt, use_senary=use_senary)
        key.lifecycle_status = KeyStatus.ACTIVE
        self.keys[key.key_id] = key
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated and stored new key with ID: {key.key_id}")
        return key

    def activate_key(self, key_id: str) -> None:
        """
        Activates a specified key, making it available for encryption operations.
        """
        key = self._get_key_or_log_error(key_id)
        if key:
            key.lifecycle_status = KeyStatus.ACTIVE
            logger.info(f"{SEIGR_CELL_ID_PREFIX} Key {key_id} activated.")

    def deactivate_key(self, key_id: str) -> None:
        """
        Deactivates a specified key, restricting its use for encryption operations.
        """
        key = self._get_key_or_log_error(key_id)
        if key:
            key.lifecycle_status = KeyStatus.INACTIVE
            logger.info(f"{SEIGR_CELL_ID_PREFIX} Key {key_id} deactivated.")

    def rotate_key(self, key_id: str, password: Optional[str] = None, use_senary: bool = True) -> Optional[SymmetricKey]:
        """
        Rotates a specified key by generating a new version and updating the stored key.
        """
        old_key = self._get_key_or_log_error(key_id)
        if not old_key:
            return None

        salt = generate_salt()
        new_key = derive_key_to_protocol(password, salt=salt, use_senary=use_senary)
        new_key.key_id = key_id  # Retain original key ID for continuity
        new_key.lifecycle_status = KeyStatus.ACTIVE
        old_key.lifecycle_status = KeyStatus.INACTIVE  # Archive the old version

        self.keys[key_id] = new_key
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Key {key_id} rotated; old version archived as inactive.")
        return new_key

    def revoke_key(self, key_id: str) -> None:
        """
        Revokes a specified key, marking it as compromised and restricting all operations.
        """
        key = self._get_key_or_log_error(key_id)
        if key:
            key.lifecycle_status = KeyStatus.REVOKED
            logger.warning(f"{SEIGR_CELL_ID_PREFIX} Key {key_id} revoked due to compromise.")

    def retrieve_key(self, key_id: str) -> Optional[SymmetricKey]:
        """
        Retrieves a key by ID if it is active or inactive, logging the access attempt.
        """
        key = self._get_key_or_log_error(key_id)
        if key and key.lifecycle_status in (KeyStatus.ACTIVE, KeyStatus.INACTIVE):
            logger.debug(f"{SEIGR_CELL_ID_PREFIX} Key {key_id} retrieved.")
            return key
        logger.warning(f"{SEIGR_CELL_ID_PREFIX} Attempt to access key {key_id} in status: {key.lifecycle_status}")
        return None

    def list_keys(self) -> List[Dict[str, str]]:
        """
        Lists all keys with their current status for monitoring purposes.
        """
        key_list = [{
            "key_id": key_id,
            "status": key.lifecycle_status,
            "creation_timestamp": key.creation_timestamp
        } for key_id, key in self.keys.items()]
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Listing all managed keys.")
        return key_list

    def _get_key_or_log_error(self, key_id: str) -> Optional[SymmetricKey]:
        """
        Helper method to retrieve a key by ID or log an error if not found.
        """
        key = self.keys.get(key_id)
        if not key:
            self._log_error("key_not_found", f"Key with ID {key_id} not found.")
        return key

    def _log_error(self, error_id: str, message: str):
        """Logs an error with detailed information."""
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Key Management",
            message=message,
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
        )
        logger.error(f"{error_log.message}")
