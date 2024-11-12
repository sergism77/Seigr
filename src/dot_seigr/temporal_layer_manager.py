# dot_seigr/temporal_layer_manager.py

import logging
from datetime import datetime, timezone
from src.crypto.hash_utils import hypha_hash
import cbor2

logger = logging.getLogger(__name__)

class TemporalLayerManager:
    def __init__(self, index):
        """
        Initializes a TemporalLayerManager to manage temporal layers of data snapshots.

        Args:
            index (int): Identifier for the segment or file.
        """
        self.index = index
        self.layers = []

    def add_layer(self, metadata, data_snapshot):
        """
        Adds a new temporal layer with a hash of the data snapshot and metadata.

        Args:
            metadata (dict): Metadata containing segment information, including segment_hash.
            data_snapshot (bytes): Snapshot of the current data state to store in the layer.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        layer_hash = hypha_hash(data_snapshot)
        self.layers.append({
            "timestamp": timestamp,
            "layer_hash": layer_hash,
            "data_snapshot": data_snapshot,
            "metadata": metadata
        })
        logger.info(f"New temporal layer added at index {self.index} with hash {layer_hash}")

    def get_latest_layer(self):
        """
        Retrieves the latest (most recent) temporal layer.

        Returns:
            dict: The latest layer if available, else None.
        """
        if self.layers:
            logger.debug("Retrieved the latest temporal layer.")
            return self.layers[-1]
        logger.warning("No temporal layers available.")
        return None

    def get_layer_by_timestamp(self, timestamp):
        """
        Retrieves a specific layer by its timestamp.

        Args:
            timestamp (str): ISO format timestamp for the target layer.

        Returns:
            dict: The temporal layer matching the timestamp, or None if not found.
        """
        for layer in self.layers:
            if layer["timestamp"] == timestamp:
                logger.debug(f"Layer found with timestamp {timestamp}")
                return layer
        logger.warning(f"No layer found with timestamp {timestamp}")
        return None

    def validate_layer_integrity(self, layer) -> bool:
        """
        Validates the integrity of a temporal layer by recalculating and comparing its hash.

        Args:
            layer (dict): Temporal layer to validate.

        Returns:
            bool: True if the recalculated hash matches the stored layer hash, False otherwise.
        """
        recalculated_hash = hypha_hash(layer["data_snapshot"])
        if layer["layer_hash"] == recalculated_hash:
            logger.info(f"Layer integrity validated for timestamp {layer['timestamp']}")
            return True
        else:
            logger.error(f"Integrity check failed for layer at timestamp {layer['timestamp']}. "
                         f"Expected: {layer['layer_hash']}, Got: {recalculated_hash}")
            return False

    def rollback_to_layer(self, target_timestamp) -> dict:
        """
        Rolls back to a specified layer based on its timestamp.

        Args:
            target_timestamp (str): Timestamp of the target layer to roll back to.

        Returns:
            dict: Data snapshot from the target layer if rollback is successful, or None if layer is not found.
        """
        target_layer = self.get_layer_by_timestamp(target_timestamp)
        if target_layer:
            logger.info(f"Rolling back to layer with timestamp {target_timestamp}")
            return target_layer["data_snapshot"]
        else:
            logger.error(f"Rollback failed: No layer found with timestamp {target_timestamp}")
            return None

    def save_layers_to_disk(self, file_path: str):
        """
        Serializes and saves all temporal layers to disk.

        Args:
            file_path (str): Path to save the serialized layers file.
        """
        try:
            with open(file_path, 'wb') as file:
                serialized_data = cbor2.dumps(self.layers)
                file.write(serialized_data)
            logger.info(f"Temporal layers saved successfully to {file_path}")
        except IOError as e:
            logger.error(f"Failed to save temporal layers to {file_path}: {e}")
            raise

    def load_layers_from_disk(self, file_path: str):
        """
        Loads temporal layers from a serialized file on disk.

        Args:
            file_path (str): Path to the file containing serialized temporal layers.
        """
        try:
            with open(file_path, 'rb') as file:
                self.layers = cbor2.loads(file.read())
            logger.info(f"Loaded temporal layers from {file_path}")
        except IOError as e:
            logger.error(f"Failed to load temporal layers from {file_path}: {e}")
            raise

    def list_layers(self) -> list[dict]:
        """
        Lists all temporal layers with their timestamps and hash values for inspection.

        Returns:
            list[dict]: List of dictionaries with timestamp and layer hash for each layer.
        """
        layers_info = [{"timestamp": layer["timestamp"], "layer_hash": layer["layer_hash"]} for layer in self.layers]
        logger.debug(f"Listing all temporal layers: {layers_info}")
        return layers_info
