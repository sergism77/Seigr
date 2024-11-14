# src/seigr_cell/seigr_cell_manager.py

import logging
from src.seigr_cell.seigr_cell_encoder import SeigrCellEncoder
from src.seigr_cell.seigr_cell_decoder import SeigrCellDecoder
from src.seigr_cell.seigr_cell_validator import SeigrCellValidator
from src.seigr_cell.seigr_cell_metadata import SeigrCellMetadata

class SeigrCellManager:
    """
    SeigrCellManager handles the lifecycle of a Seigr Cell, managing its creation, encoding,
    decoding, validation, and metadata. Aligned with Seigr's modular, resilient data structure.
    """

    def __init__(self, segment_id: str = "default_segment", hash_depth: int = 4, use_senary: bool = True):
        """
        Initializes SeigrCellManager with optional cryptographic parameters.

        Args:
            segment_id (str): Identifier for the data segment, passed to encoder/decoder.
            hash_depth (int): Depth of hierarchical hashing, cascades to encoder/decoder.
            use_senary (bool): Whether to use senary encoding, cascades to encoder/decoder.
        """
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary

        # Initialize encoder, decoder, validator, and metadata manager with configurations
        self.encoder = SeigrCellEncoder(segment_id, hash_depth, use_senary)
        self.decoder = SeigrCellDecoder(segment_id, hash_depth, use_senary)
        self.validator = SeigrCellValidator()
        self.metadata_manager = SeigrCellMetadata()
        
        # Logging setup for monitoring cell actions
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        self.logger.info(f"Initialized SeigrCellManager with segment_id={segment_id}, hash_depth={hash_depth}, use_senary={use_senary}.")

    def create_seigr_cell(self, data: bytes, initial_metadata: dict = None, password: str = None) -> bytes:
        """
        Initializes a new Seigr Cell with data, optional metadata, and optional password protection.

        Args:
            data (bytes): The raw data to be encapsulated in a Seigr Cell.
            initial_metadata (dict): Optional metadata dictionary to include with the cell.
            password (str): Optional password for encryption.

        Returns:
            bytes: Encoded Seigr Cell ready for network interaction.
        """
        self.logger.info("Creating a new Seigr Cell.")
        
        # Generate or retrieve initial metadata
        metadata = initial_metadata or self.metadata_manager.generate_default_metadata()

        # Encode data into Seigr Cell format with encryption and integrity
        try:
            encoded_cell = self.encoder.encode(data, metadata, password=password)
            self.logger.info("Seigr Cell encoded successfully.")
        except Exception as e:
            self.logger.error(f"Failed to encode Seigr Cell: {e}")
            raise ValueError("Encoding failed during Seigr Cell creation.")

        # Validate the structure of the newly created cell
        if self.validate_seigr_cell(encoded_cell):
            self.logger.info("Seigr Cell created and validated successfully.")
            return encoded_cell
        else:
            self.logger.error("Seigr Cell validation failed post-creation.")
            raise ValueError("Invalid Seigr Cell structure post-creation.")

    def encode_seigr_cell(self, data: bytes, metadata: dict, password: str = None) -> bytes:
        """
        Encodes data and metadata into Seigr Cell format with optional encryption.

        Args:
            data (bytes): Data to be encoded into the Seigr Cell.
            metadata (dict): Metadata to attach to the Seigr Cell.
            password (str): Optional password for encryption.

        Returns:
            bytes: Encoded Seigr Cell.
        """
        self.logger.info("Encoding data into Seigr Cell.")
        try:
            return self.encoder.encode(data, metadata, password=password)
        except Exception as e:
            self.logger.error(f"Failed to encode Seigr Cell: {e}")
            raise ValueError("Encoding failed for Seigr Cell.")

    def decode_seigr_cell(self, encoded_cell: bytes, password: str = None) -> tuple:
        """
        Decodes an encoded Seigr Cell back into raw data and metadata with optional decryption.

        Args:
            encoded_cell (bytes): The Seigr Cell to decode.
            password (str): Optional password for decryption.

        Returns:
            tuple: Decoded data (bytes) and metadata (dict).
        """
        self.logger.info("Decoding Seigr Cell.")
        try:
            return self.decoder.decode(encoded_cell, password=password)
        except Exception as e:
            self.logger.error(f"Failed to decode Seigr Cell: {e}")
            raise ValueError("Decoding failed for Seigr Cell.")

    def validate_seigr_cell(self, encoded_cell: bytes) -> bool:
        """
        Validates the integrity and structure of a Seigr Cell.

        Args:
            encoded_cell (bytes): The Seigr Cell to validate.

        Returns:
            bool: True if the cell is valid, False otherwise.
        """
        self.logger.info("Validating Seigr Cell.")
        is_valid = self.validator.validate(encoded_cell)
        self.logger.info(f"Seigr Cell validation result: {'Valid' if is_valid else 'Invalid'}")
        return is_valid

    def get_metadata(self, encoded_cell: bytes) -> dict:
        """
        Retrieves metadata from a Seigr Cell for traceability and lineage purposes.

        Args:
            encoded_cell (bytes): The Seigr Cell from which to extract metadata.

        Returns:
            dict: Metadata extracted from the Seigr Cell.
        """
        self.logger.info("Extracting metadata from Seigr Cell.")
        return self.metadata_manager.extract_metadata(encoded_cell)

    def update_metadata(self, encoded_cell: bytes, updates: dict) -> bytes:
        """
        Updates metadata within a Seigr Cell, supporting adaptive replication and lineage tracking.

        Args:
            encoded_cell (bytes): The Seigr Cell to update.
            updates (dict): Dictionary of metadata updates.

        Returns:
            bytes: Updated Seigr Cell with new metadata.
        """
        self.logger.info("Updating metadata within Seigr Cell.")

        # Extract current metadata, apply updates, and re-encode the cell
        current_metadata = self.get_metadata(encoded_cell)
        updated_metadata = self.metadata_manager.update_metadata(current_metadata, updates)
        
        # Retrieve the data for re-encoding with updated metadata
        data, _ = self.decode_seigr_cell(encoded_cell)
        
        # Encode the updated cell with the new metadata
        return self.encode_seigr_cell(data, updated_metadata)
