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

    def sync_state(self, state_id: str, state_data: Dict[str, Any]) -> bool:
        """
        Synchronizes a given state with the central repository or other nodes.

        Args:
            state_id (str): Unique identifier for the state.
            state_data (Dict[str, Any]): Data representing the state to be synced.

        Returns:
            bool: True if the sync was successful, False otherwise.
        """
        try:
            logger.info(f"Syncing state with ID: {state_id}")
            with self.lock:
                self.local_states[state_id] = state_data
                self.synced_states[state_id] = state_data

            secure_logger.log_audit_event(
                severity=1,
                category="Synchronization",
                message=f"State {state_id} synchronized successfully.",
                sensitive=False,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to sync state {state_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Synchronization",
                message=f"Failed to sync state {state_id}: {e}",
                sensitive=True,
            )
            return False

    def retrieve_synced_state(self, state_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a synced state by its unique identifier.

        Args:
            state_id (str): Unique identifier for the state.

        Returns:
            Optional[Dict[str, Any]]: The synced state data, or None if not found.
        """
        logger.info(f"Retrieving synced state with ID: {state_id}")
        with self.lock:
            state = self.synced_states.get(state_id)

        if state:
            logger.debug(f"Synced state retrieved: {state_id}")
            return state

        logger.warning(f"Synced state not found: {state_id}")
        return None

    def resolve_conflicts(self, state_id: str, incoming_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolves conflicts between local and incoming states.

        Args:
            state_id (str): Unique identifier for the state.
            incoming_state (Dict[str, Any]): Incoming state data to be resolved.

        Returns:
            Dict[str, Any]: The resolved state data.
        """
        try:
            logger.info(f"Resolving conflicts for state ID: {state_id}")
            with self.lock:
                local_state = self.local_states.get(state_id, {})
                resolved_state = self._merge_states(local_state, incoming_state)
                self.local_states[state_id] = resolved_state
                self.synced_states[state_id] = resolved_state

            logger.info(f"Conflicts resolved for state ID: {state_id}")
            return resolved_state
        except Exception as e:
            logger.error(f"Failed to resolve conflicts for state ID {state_id}: {e}")
            self.conflict_log[state_id] = {
                "local_state": self.local_states.get(state_id),
                "incoming_state": incoming_state,
                "error": str(e),
            }
            raise

    def _merge_states(
        self, local_state: Dict[str, Any], incoming_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merges two states with conflict resolution logic.

        Args:
            local_state (Dict[str, Any]): The current local state.
            incoming_state (Dict[str, Any]): The incoming state to merge.

        Returns:
            Dict[str, Any]: The merged state.
        """
        merged_state = {}
        for key in set(local_state.keys()).union(incoming_state.keys()):
            if key not in local_state:
                merged_state[key] = incoming_state[key]
            elif key not in incoming_state:
                merged_state[key] = local_state[key]
            else:
                if isinstance(local_state[key], dict) and isinstance(incoming_state[key], dict):
                    merged_state[key] = self._merge_states(local_state[key], incoming_state[key])
                elif incoming_state.get("timestamp", "") > local_state.get("timestamp", ""):
                    merged_state[key] = incoming_state[key]
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
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            json_data = json.dumps(export_data, indent=4)
            logger.info("Exported synced states successfully.")
            return json_data
        except Exception as e:
            logger.error(f"Failed to export synced states: {e}")
            raise
