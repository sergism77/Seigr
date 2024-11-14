# src/seigr_cell/seigr_cell_metadata.py

import logging
from datetime import datetime, timezone
from src.crypto.helpers import generate_metadata

# Initialize logger for metadata management
logger = logging.getLogger(__name__)

class SeigrCellMetadata:
    """
    SeigrCellMetadata manages the creation, extraction, and updating of metadata within Seigr Cells.
    """

    def __init__(self):
        self.logger = logger
        self.logger.info("Initialized SeigrCellMetadata manager.")

    def generate_default_metadata(self) -> dict:
        """
        Generates a default set of metadata, including creation timestamp and unique identifiers.

        Returns:
            dict: Default metadata for a new Seigr Cell.
        """
        default_metadata = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "cell_id": generate_metadata("SCELL"),
            "version": "1.0",
            "status": "active",
            "tags": [],
            "lineage": {"origin": "created", "last_updated": datetime.now(timezone.utc).isoformat()}
        }
        self.logger.debug(f"Generated default metadata: {default_metadata}")
        return default_metadata

    def extract_metadata(self, encoded_cell: bytes) -> dict:
        """
        Extracts metadata from an encoded Seigr Cell.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell from which metadata will be extracted.

        Returns:
            dict: Extracted metadata from the Seigr Cell.
        """
        try:
            # Decode to retrieve the payload and access metadata
            payload = self._decode_cell_payload(encoded_cell)
            metadata = payload.get("metadata", {})
            self.logger.info("Extracted metadata from Seigr Cell.")
            return metadata
        except Exception as e:
            self.logger.error(f"Failed to extract metadata from Seigr Cell: {e}")
            raise ValueError("Error extracting metadata from Seigr Cell")

    def update_metadata(self, current_metadata: dict, updates: dict) -> dict:
        """
        Updates the metadata of a Seigr Cell with specified updates.

        Args:
            current_metadata (dict): Current metadata dictionary from the Seigr Cell.
            updates (dict): Dictionary containing updates to apply to the metadata.

        Returns:
            dict: Updated metadata dictionary.
        """
        try:
            # Apply updates to the existing metadata, ensuring critical fields remain consistent
            updated_metadata = current_metadata.copy()
            updated_metadata.update(updates)

            # Automatically update the lineage and timestamp fields
            updated_metadata["lineage"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            updated_metadata["version"] = self._increment_version(current_metadata.get("version", "1.0"))
            
            self.logger.debug(f"Updated metadata: {updated_metadata}")
            return updated_metadata
        except Exception as e:
            self.logger.error(f"Failed to update metadata: {e}")
            raise ValueError("Error updating metadata in Seigr Cell")

    def _decode_cell_payload(self, encoded_cell: bytes) -> dict:
        """
        Decodes the payload from an encoded Seigr Cell to retrieve its contents.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell to decode.

        Returns:
            dict: Decoded payload from the Seigr Cell.
        """
        # We assume that SeigrCellDecoder’s decode method is used here
        from src.seigr_cell.seigr_cell_decoder import SeigrCellDecoder
        
        decoder = SeigrCellDecoder(segment_id="metadata_retrieval")
        _, payload = decoder.decode(encoded_cell)
        
        self.logger.debug("Decoded Seigr Cell payload for metadata extraction.")
        return payload

    def _increment_version(self, current_version: str) -> str:
        """
        Increments the version of the metadata in a semantic manner.

        Args:
            current_version (str): Current version string (e.g., "1.0").

        Returns:
            str: New version string with incremented minor version.
        """
        try:
            major, minor = map(int, current_version.split("."))
            new_version = f"{major}.{minor + 1}"
            self.logger.debug(f"Incremented version from {current_version} to {new_version}")
            return new_version
        except ValueError:
            self.logger.warning("Invalid version format; resetting to 1.0")
            return "1.0"
