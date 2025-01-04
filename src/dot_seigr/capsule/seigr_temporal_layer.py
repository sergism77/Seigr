import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.crypto.hash_utils import hypha_hash
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    SegmentMetadata,
    TemporalLayer,
)

logger = logging.getLogger(__name__)


class SeigrTemporalLayer:
    """
    Manages temporal layers for Seigr segments, allowing creation, validation, rollback, and
    persistence of time-based snapshots.
    """

    def __init__(self):
        """
        Initializes a SeigrTemporalLayer instance to manage time-based snapshots of segments.
        """
        self.layers: List[TemporalLayer] = []

    def create_layer(self, segments: List[SegmentMetadata]) -> TemporalLayer:
        """
        Creates a new temporal layer based on the provided list of segment metadata.

        Args:
            segments (List[SegmentMetadata]): List of SegmentMetadata objects representing the current state.

        Returns:
            TemporalLayer: The newly created temporal layer.
        """
        layer_timestamp = datetime.now(timezone.utc).isoformat()
        layer_hash = self._compute_layer_hash(segments)

        temporal_layer = TemporalLayer(timestamp=layer_timestamp, layer_hash=layer_hash)
        temporal_layer.segments.extend(segments)

        self.layers.append(temporal_layer)
        logger.info(
            f"Created new temporal layer at {layer_timestamp} with hash {layer_hash}"
        )
        return temporal_layer

    def get_latest_layer(self) -> Optional[TemporalLayer]:
        """
        Retrieves the most recent temporal layer.

        Returns:
            Optional[TemporalLayer]: The latest temporal layer if available, otherwise None.
        """
        if self.layers:
            logger.debug("Retrieved the latest temporal layer.")
            return self.layers[-1]
        logger.warning("No temporal layers available.")
        return None

    def validate_layer_integrity(self, layer: TemporalLayer) -> bool:
        """
        Validates the integrity of a temporal layer by recalculating and comparing its hash.

        Args:
            layer (TemporalLayer): The temporal layer to validate.

        Returns:
            bool: True if the recalculated hash matches the layer's hash, False otherwise.
        """
        recalculated_hash = self._compute_layer_hash(layer.segments)

        if layer.layer_hash == recalculated_hash:
            logger.info(
                f"Temporal layer integrity validated for layer created at {layer.timestamp}."
            )
            return True
        else:
            logger.error(
                f"Temporal layer integrity failed for layer created at {layer.timestamp}. "
                f"Expected: {layer.layer_hash}, Got: {recalculated_hash}"
            )
            return False

    def rollback_to_layer(self, target_layer: TemporalLayer) -> List[SegmentMetadata]:
        """
        Rolls back to a specified temporal layer, returning the segment metadata of that layer.

        Args:
            target_layer (TemporalLayer): The temporal layer to roll back to.

        Returns:
            List[SegmentMetadata]: List of SegmentMetadata from the target layer.
        """
        if target_layer in self.layers:
            logger.info(
                f"Rolling back to temporal layer created at {target_layer.timestamp}."
            )
            return list(target_layer.segments)
        else:
            logger.error("Specified temporal layer not found.")
            raise ValueError(
                "Target layer does not exist in the current layer history."
            )

    def save_temporal_layers(self, file_path: str):
        """
        Saves the list of temporal layers to disk as a serialized file.

        Args:
            file_path (str): Path to save the serialized temporal layers file.
        """
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        try:
            with open(file_path, "wb") as file:
                file.write(
                    b"".join([layer.SerializeToString() for layer in self.layers])
                )
            logger.info(f"Temporal layers saved successfully to {file_path}")
        except IOError as e:
            logger.error(f"Failed to save temporal layers at {file_path}: {e}")
            raise

    def load_temporal_layers(self, file_path: str):
        """
        Loads temporal layers from a serialized file on disk.

        Args:
            file_path (str): Path to the file containing serialized temporal layers.
        """
        try:
            with open(file_path, "rb") as file:
                data = file.read()
                self.layers.clear()
                offset = 0
                while offset < len(data):
                    layer = TemporalLayer()
                    next_offset = layer.ParseFromString(data[offset:])
                    if next_offset == 0:
                        logger.error("Error parsing layer data.")
                        break
                    offset += next_offset
                    self.layers.append(layer)
            logger.info(f"Loaded temporal layers from {file_path}")
        except IOError as e:
            logger.error(f"Failed to load temporal layers from {file_path}: {e}")
            raise

    def list_layers(self) -> List[Dict[str, str]]:
        """
        Lists all temporal layers with their timestamps and hash values for inspection.

        Returns:
            List[Dict[str, str]]: A list of dictionaries with timestamp and layer hash for each layer.
        """
        layers_info = [
            {"timestamp": layer.timestamp, "hash": layer.layer_hash}
            for layer in self.layers
        ]
        logger.debug(f"Listing all temporal layers: {layers_info}")
        return layers_info

    @staticmethod
    def _compute_layer_hash(segments: List[SegmentMetadata]) -> str:
        """
        Computes a unique hash for the given list of segment metadata.

        Args:
            segments (List[SegmentMetadata]): List of SegmentMetadata objects.

        Returns:
            str: The computed hash for the segments.
        """
        combined_segment_hashes = "".join(
            [segment.segment_hash for segment in segments]
        )
        return hypha_hash(combined_segment_hashes.encode())
