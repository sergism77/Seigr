import logging
from .lineage_serializer import LineageSerializer
from src.seigr_protocol.compiled.lineage_pb2 import Lineage as LineageProto
from typing import Dict, Any

logger = logging.getLogger(__name__)


class LineageStorage:
    """
    Manages the persistence of Lineage data, handling saving to and loading from disk.
    """

    @staticmethod
    def save_to_disk(lineage, storage_path: str) -> None:
        """
        Saves a Lineage instance to disk as a serialized Protobuf file.

        Args:
            lineage (Lineage): The Lineage instance to serialize and save.
            storage_path (str): Path on disk to save the serialized lineage file.

        Raises:
            IOError: If an I/O error occurs during file writing.
        """
        try:
            lineage_proto = LineageSerializer.to_protobuf(lineage)
            with open(storage_path, "wb") as file:
                file.write(lineage_proto.SerializeToString())
            logger.info(f"Lineage saved successfully at {storage_path}")
        except IOError as e:
            logger.error(f"Failed to save lineage to {storage_path}: {e}")
            raise IOError(f"Error saving lineage to {storage_path}") from e

    @staticmethod
    def load_from_disk(storage_path: str) -> Dict[str, Any]:
        """
        Loads a Lineage instance from a serialized Protobuf file on disk.

        Args:
            storage_path (str): Path to the serialized lineage file.

        Returns:
            dict: A dictionary representing the loaded lineage data.

        Raises:
            IOError: If the file cannot be opened or read.
            ValueError: If deserialization from Protobuf fails.
        """
        lineage_proto = LineageProto()
        try:
            with open(storage_path, "rb") as file:
                lineage_proto.ParseFromString(file.read())
            logger.info(f"Lineage loaded successfully from {storage_path}")
            return LineageSerializer.from_protobuf(lineage_proto)
        except IOError as e:
            logger.error(f"Failed to open or read lineage file at {storage_path}: {e}")
            raise IOError(f"Error loading lineage file at {storage_path}") from e
        except ValueError as e:
            logger.error(f"Failed to parse lineage data from Protobuf: {e}")
            raise ValueError("Invalid Protobuf format in lineage file") from e
