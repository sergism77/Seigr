# src/dot_seigr/temporal/temporal_layer_manager.py

import logging
import cbor2
from typing import Dict, List, Optional

from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime, timezone

from src.crypto.hypha_crypt import HyphaCrypt  # Ensuring proper hash computation
from src.logger.secure_logger import secure_logger  # ✅ Using Seigr's structured logger

class TemporalLayerManager:
    """
    Manages temporal layers for snapshots of data states with integrity validation and disk persistence.
    """

    def __init__(self, index: int):
        """
        Initializes a TemporalLayerManager to manage temporal layers of data snapshots.

        Args:
            index (int): Identifier for the segment or file.
        """
        self.index = index
        self.layers: List[Dict[str, any]] = []

        secure_logger.log_audit_event(
            "info", "TemporalLayerManager",
            f"✅ TemporalLayerManager initialized for index {self.index}"
        )

    def add_layer(self, metadata: dict, data_snapshot: bytes):
        """
        Adds a new temporal layer with a hash of the data snapshot and metadata.

        Args:
            metadata (dict): Metadata containing segment information, including segment_hash.
            data_snapshot (bytes): Snapshot of the current data state to store in the layer.
        """
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        crypt = HyphaCrypt(data=b"", segment_id="temporal_layer")
        layer_hash = crypt.hypha_hash(data_snapshot)

        new_layer = {
            "timestamp": timestamp_proto.ToJsonString(),
            "layer_hash": layer_hash,
            "data_snapshot": data_snapshot,
            "metadata": metadata,
        }

        self.layers.append(new_layer)

        secure_logger.log_audit_event(
            "info", "TemporalLayerManager",
            f"✅ New temporal layer added at index {self.index} with hash {layer_hash}"
        )

    def get_latest_layer(self) -> Optional[Dict]:
        """
        Retrieves the latest (most recent) temporal layer.

        Returns:
            Optional[Dict]: The latest layer if available, otherwise None.
        """
        if self.layers:
            secure_logger.log_audit_event("debug", "TemporalLayerManager", "🔵 Retrieved the latest temporal layer.")
            return self.layers[-1]
        secure_logger.log_audit_event("warning", "TemporalLayerManager", "⚠️ No temporal layers available.")
        return None

    def get_layer_by_timestamp(self, timestamp: str) -> Optional[Dict]:
        """
        Retrieves a specific layer by its timestamp.

        Args:
            timestamp (str): ISO format timestamp for the target layer.

        Returns:
            Optional[Dict]: The temporal layer matching the timestamp, or None if not found.
        """
        target_layer = next(
            (layer for layer in self.layers if layer["timestamp"] == timestamp), None
        )
        if target_layer:
            secure_logger.log_audit_event("debug", "TemporalLayerManager", f"🔍 Layer found with timestamp {timestamp}")
            return target_layer
        secure_logger.log_audit_event("warning", "TemporalLayerManager", f"⚠️ No layer found with timestamp {timestamp}")
        return None

    def validate_layer_integrity(self, layer: Dict) -> bool:
        """
        Validates the integrity of a temporal layer by recalculating and comparing its hash.

        Args:
            layer (dict): Temporal layer to validate.

        Returns:
            bool: True if the recalculated hash matches the stored layer hash, False otherwise.
        """
        crypt = HyphaCrypt(data=b"", segment_id="temporal_layer")
        recalculated_hash = crypt.hypha_hash(layer["data_snapshot"])
        is_valid = layer["layer_hash"] == recalculated_hash

        if is_valid:
            secure_logger.log_audit_event("info", "TemporalLayerManager", f"✅ Layer integrity validated for timestamp {layer['timestamp']}")
        else:
            secure_logger.log_audit_event(
                "error", "TemporalLayerManager",
                f"❌ Integrity check failed for layer at timestamp {layer['timestamp']}. "
                f"Expected: {layer['layer_hash']}, Got: {recalculated_hash}"
            )

        return is_valid

    def rollback_to_layer(self, target_timestamp: str) -> Optional[bytes]:
        """
        Rolls back to a specified layer based on its timestamp.

        Args:
            target_timestamp (str): Timestamp of the target layer to roll back to.

        Returns:
            Optional[bytes]: Data snapshot from the target layer if rollback is successful, or None if layer is not found.
        """
        target_layer = self.get_layer_by_timestamp(target_timestamp)
        if target_layer:
            secure_logger.log_audit_event("info", "TemporalLayerManager", f"🔄 Rolling back to layer with timestamp {target_timestamp}")
            return target_layer["data_snapshot"]
        else:
            secure_logger.log_audit_event("error", "TemporalLayerManager", f"❌ Rollback failed: No layer found with timestamp {target_timestamp}")
            return None

    def save_layers_to_disk(self, file_path: str):
        """
        Serializes and saves all temporal layers to disk.

        Args:
            file_path (str): Path to save the serialized layers file.
        """
        try:
            with open(file_path, "wb") as file:
                file.write(cbor2.dumps(self.layers))
            secure_logger.log_audit_event("info", "TemporalLayerManager", f"✅ Temporal layers saved successfully to {file_path}")
        except IOError as e:
            secure_logger.log_audit_event("error", "TemporalLayerManager", f"❌ Failed to save temporal layers to {file_path}: {e}")
            raise

    def load_layers_from_disk(self, file_path: str):
        """
        Loads temporal layers from a serialized file on disk.

        Args:
            file_path (str): Path to the file containing serialized temporal layers.
        """
        try:
            with open(file_path, "rb") as file:
                self.layers = cbor2.loads(file.read())
            secure_logger.log_audit_event("info", "TemporalLayerManager", f"✅ Loaded temporal layers from {file_path}")
        except IOError as e:
            secure_logger.log_audit_event("error", "TemporalLayerManager", f"❌ Failed to load temporal layers from {file_path}: {e}")
            raise

    def list_layers(self) -> List[Dict[str, str]]:
        """
        Lists all temporal layers with their timestamps and hash values for inspection.

        Returns:
            List[Dict[str, str]]: List of dictionaries with timestamp and layer hash for each layer.
        """
        layers_info = [
            {"timestamp": layer["timestamp"], "layer_hash": layer["layer_hash"]}
            for layer in self.layers
        ]
        secure_logger.log_audit_event("debug", "TemporalLayerManager", f"📜 Listing all temporal layers: {layers_info}")
        return layers_info
