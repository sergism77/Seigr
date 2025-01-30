import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from threading import Lock
from src.seigr_protocol.compiled.noesis_pb2 import NoesisConfig
from src.logger.secure_logger import secure_logger

logger = logging.getLogger(__name__)


class SyncManager:
    """
    Manages synchronization of Noesis states across different nodes,
    ensuring consistency, conflict resolution, and efficient state sharing.
    """

    def __init__(self):
        """
        Initializes the SyncManager with in-memory storage for state synchronization.
        """
        self.local_states: Dict[str, Dict[str, Any]] = {}
        self.synced_states: Dict[str, Dict[str, Any]] = {}
        self.conflict_log: Dict[str, Any] = {}
        self.lock = Lock()  # Thread-safe access to shared states
        logger.info("SyncManager initialized successfully.")

    def _ensure_datetime(self, timestamp: Any) -> datetime:
        """Ensures that the input timestamp is a valid `datetime` object."""
        logger.debug(
            f"🔎 DEBUG: Validating timestamp -> {timestamp} (type: {type(timestamp).__name__})"
        )

        if timestamp is None:
            return datetime.now(timezone.utc)  # ✅ Default to UTC datetime

        if isinstance(timestamp, datetime):
            return timestamp  # ✅ Already a datetime

        if isinstance(timestamp, str):
            try:
                # ✅ Normalize "Z" to "+00:00" before parsing
                converted_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
                    timezone.utc
                )
                logger.debug(
                    f"✅ Converted string timestamp to datetime -> {converted_dt} (type: {type(converted_dt).__name__})"
                )
                return converted_dt
            except ValueError:
                logger.error(f"❌ Invalid timestamp format received -> {timestamp}")
                raise ValueError(f"Invalid timestamp format: {timestamp}")

        logger.error(
            f"❌ Unexpected timestamp type -> {type(timestamp).__name__}, value: {timestamp}"
        )
        raise TypeError(f"Timestamp must be str or datetime, got {type(timestamp).__name__}")

    def sync_state(self, state_id: str, state_data: Dict[str, Any]) -> bool:
        """
        Synchronizes a given state with the central repository or other nodes.
        """
        try:
            logger.info(f"🔄 Syncing state with ID: {state_id}")

            # 🛠 Log initial raw timestamp value
            raw_timestamp = state_data.get("timestamp")
            logger.debug(
                f"🛠 Raw timestamp before conversion: {raw_timestamp} (type: {type(raw_timestamp).__name__})"
            )

            with self.lock:
                self.local_states[state_id] = state_data
                self.synced_states[state_id] = state_data

            # ✅ Ensure timestamp is passed through `_ensure_datetime()` before logging
            timestamp_value = self._ensure_datetime(state_data.get("timestamp"))

            # ✅ Debug log before passing to `secure_logger`
            logger.debug(
                f"🔎 DEBUG: Final timestamp before logging -> {timestamp_value} (type: {type(timestamp_value).__name__})"
            )

            # 🚨 Catch Reassignment 🚨
            if isinstance(timestamp_value, str):
                raise TypeError(
                    f"❌ ERROR: Timestamp was converted to a string BEFORE logging! Value: {timestamp_value}"
                )

            # ✅ Log audit event with validated timestamp
            secure_logger.log_audit_event(
                severity=1,
                category="Synchronization",
                message=f"State {state_id} synchronized successfully.",
                sensitive=False,
                timestamp=timestamp_value,  # ✅ Always datetime
            )

            return True

        except Exception as e:
            logger.error(f"❌ Failed to sync state {state_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Synchronization",
                message=f"Failed to sync state {state_id}: {e}",
                sensitive=True,
            )
            return False

    def _merge_states(
        self, local_state: Dict[str, Any], incoming_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        merged_state = {}
        for key in set(local_state.keys()).union(incoming_state.keys()):
            if key not in local_state:
                merged_state[key] = incoming_state[key]
            elif key not in incoming_state:
                merged_state[key] = local_state[key]
            else:
                if isinstance(local_state[key], dict) and isinstance(incoming_state[key], dict):
                    merged_state[key] = self._merge_states(local_state[key], incoming_state[key])
                elif key == "timestamp":  # ✅ Use centralized timestamp validation
                    local_ts = self._ensure_datetime(local_state[key])
                    incoming_ts = self._ensure_datetime(incoming_state[key])
                    merged_state[key] = (
                        incoming_ts if incoming_ts > local_ts else local_ts
                    )  # ✅ Always datetime
                else:
                    merged_state[key] = local_state[key]
        return merged_state

    def list_synced_states(self) -> Dict[str, Dict[str, Any]]:
        """
        Lists all currently synced states.

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of all synced states.
        """
        logger.info("Listing all synced states.")
        with self.lock:
            return self.synced_states.copy()

    def clear_synced_states(self):
        """
        Clears all synced states from memory.
        """
        logger.warning("Clearing all synced states.")
        with self.lock:
            self.synced_states.clear()
        secure_logger.log_audit_event(
            severity=2,
            category="Synchronization",
            message="All synced states cleared.",
            sensitive=False,
        )

    def export_synced_states(self) -> str:
        """
        Exports all synced states as a JSON string.

        Returns:
            str: JSON representation of all synced states.
        """
        try:
            with self.lock:
                export_data = {
                    "synced_states": self.synced_states,
                    "timestamp": datetime.now(timezone.utc),
                }

            json_data = json.dumps(export_data, indent=4)
            logger.info("Exported synced states successfully.")
            return json_data
        except Exception as e:
            logger.error(f"Failed to export synced states: {e}")
            raise
