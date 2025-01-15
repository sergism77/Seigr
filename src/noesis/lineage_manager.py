import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class LineageManager:
    """
    Manages the lineage of states within the Noesis system, enabling
    traceability, rollback, auditing, and emergent intelligence evolution.
    """

    def __init__(self):
        """
        Initializes the LineageManager with in-memory storage for lineage data.
        """
        self.lineage_data: Dict[str, List[Dict[str, Any]]] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self.snapshots: Dict[str, Dict[str, Any]] = {}  # Stores snapshots for quick rollback
        logger.info("LineageManager initialized successfully.")

    def add_entry(self, state_id: str, state_data: Dict[str, Any], metadata: Dict[str, Any] = None) -> None:
        """
        Adds a new entry to the lineage for a given state.

        Args:
            state_id (str): Unique identifier of the state.
            state_data (Dict[str, Any]): The state data to add to the lineage.
            metadata (Dict[str, Any], optional): Additional metadata for the entry.
        """
        try:
            timestamp = datetime.utcnow().isoformat()
            entry = {
                "timestamp": timestamp,
                "state_data": state_data,
                "metadata": metadata or {},
            }
            if state_id not in self.lineage_data:
                self.lineage_data[state_id] = []
            self.lineage_data[state_id].append(entry)

            # Update metadata for the state
            if state_id not in self.metadata:
                self.metadata[state_id] = {}
            self.metadata[state_id].update(metadata or {})

            # Create a snapshot for quick rollback
            self.snapshots[state_id] = state_data

            logger.info(f"Lineage entry added for state ID: {state_id}")
        except Exception as e:
            logger.error(f"Failed to add lineage entry for state ID {state_id}: {e}")
            raise

    def get_lineage(self, state_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves the lineage of a given state.

        Args:
            state_id (str): Unique identifier of the state.

        Returns:
            List[Dict[str, Any]]: The lineage data for the specified state.
        """
        try:
            if state_id not in self.lineage_data:
                raise ValueError(f"No lineage data found for state ID {state_id}.")
            logger.info(f"Retrieved lineage for state ID: {state_id}")
            return self.lineage_data[state_id]
        except Exception as e:
            logger.error(f"Failed to retrieve lineage for state ID {state_id}: {e}")
            raise

    def rollback_state(self, state_id: str, timestamp: str) -> Dict[str, Any]:
        """
        Rolls back a state to a specific timestamp.

        Args:
            state_id (str): Unique identifier of the state.
            timestamp (str): Timestamp to roll back to.

        Returns:
            Dict[str, Any]: The rolled-back state data.
        """
        try:
            if state_id not in self.lineage_data:
                raise ValueError(f"No lineage data found for state ID {state_id}.")

            lineage = self.lineage_data[state_id]
            rollback_entry = next(
                (entry for entry in lineage if entry["timestamp"] == timestamp),
                None,
            )

            if rollback_entry is None:
                raise ValueError(f"No entry found for timestamp {timestamp} in state ID {state_id}.")

            self.snapshots[state_id] = rollback_entry["state_data"]  # Update snapshot
            logger.info(f"State ID {state_id} rolled back to timestamp {timestamp}.")
            return rollback_entry["state_data"]
        except Exception as e:
            logger.error(f"Failed to roll back state ID {state_id} to timestamp {timestamp}: {e}")
            raise

    def list_states(self) -> List[str]:
        """
        Lists all state IDs currently tracked in the lineage.

        Returns:
            List[str]: List of state IDs.
        """
        try:
            state_ids = list(self.lineage_data.keys())
            logger.info("Retrieved list of tracked state IDs.")
            return state_ids
        except Exception as e:
            logger.error(f"Failed to retrieve list of state IDs: {e}")
            raise

    def clear_lineage(self, state_id: str) -> None:
        """
        Clears the lineage data for a specific state.

        Args:
            state_id (str): Unique identifier of the state to clear.
        """
        try:
            if state_id in self.lineage_data:
                del self.lineage_data[state_id]
                del self.metadata[state_id]
                del self.snapshots[state_id]
                logger.info(f"Cleared lineage data for state ID: {state_id}")
            else:
                logger.warning(f"No lineage data found for state ID: {state_id}")
        except Exception as e:
            logger.error(f"Failed to clear lineage data for state ID {state_id}: {e}")
            raise

    def get_metadata(self, state_id: str) -> Dict[str, Any]:
        """
        Retrieves metadata for a specific state.

        Args:
            state_id (str): Unique identifier of the state.

        Returns:
            Dict[str, Any]: Metadata for the state.
        """
        try:
            if state_id not in self.metadata:
                raise ValueError(f"No metadata found for state ID {state_id}.")
            logger.info(f"Retrieved metadata for state ID: {state_id}")
            return self.metadata[state_id]
        except Exception as e:
            logger.error(f"Failed to retrieve metadata for state ID {state_id}: {e}")
            raise

    def export_lineage(self, state_id: str) -> str:
        """
        Exports the lineage data for a given state as a JSON string.

        Args:
            state_id (str): Unique identifier of the state.

        Returns:
            str: JSON string containing the lineage data.
        """
        try:
            import json

            if state_id not in self.lineage_data:
                raise ValueError(f"No lineage data found for state ID {state_id}.")

            export_data = {
                "state_id": state_id,
                "lineage": self.lineage_data[state_id],
                "metadata": self.metadata.get(state_id, {}),
                "snapshot": self.snapshots.get(state_id, {}),
            }
            json_data = json.dumps(export_data, indent=4)
            logger.info(f"Exported lineage data for state ID: {state_id}")
            return json_data
        except Exception as e:
            logger.error(f"Failed to export lineage data for state ID {state_id}: {e}")
            raise
