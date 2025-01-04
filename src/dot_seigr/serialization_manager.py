# src/dot_seigr/serialization_manager.py

import logging
import os

import cbor2

from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import FileMetadata, SeedDotSeigr

logger = logging.getLogger(__name__)


class SerializationManager:
    """
    Manages serialization and deserialization of `.seigr` files.
    Supports both CBOR and Protobuf formats for storage flexibility.
    """

    def save(self, seigr_file, base_dir: str, use_cbor: bool = False) -> str:
        """
        Saves the `.seigr` file, using either CBOR or Protobuf format.

        Args:
            seigr_file: The `.seigr` file instance to save.
            base_dir (str): Directory to save the serialized file.
            use_cbor (bool): If True, uses CBOR format; otherwise, Protobuf.

        Returns:
            str: Path to the saved file.

        Raises:
            IOError: If there is an issue saving the file to disk.
        """
        ext = "cbor" if use_cbor else "pb"
        filename = f"{seigr_file.creator_id}_{seigr_file.index}.seigr.{ext}"
        file_path = os.path.join(base_dir, filename)

        os.makedirs(base_dir, exist_ok=True)
        try:
            with open(file_path, "wb") as f:
                f.write(self.serialize(seigr_file, use_cbor))
            logger.info(f"Serialized file saved at {file_path}")
            return file_path
        except IOError as e:
            logger.error(f"Failed to save serialized file at {file_path}: {e}")
            raise

    def serialize(self, seigr_file, use_cbor: bool = False) -> bytes:
        """
        Serializes a `.seigr` file to either CBOR or Protobuf format.

        Args:
            seigr_file: The `.seigr` file instance to serialize.
            use_cbor (bool): If True, uses CBOR format; otherwise, Protobuf.

        Returns:
            bytes: Serialized data in the specified format.

        Raises:
            ValueError: If serialization fails due to incompatible data format.
        """
        metadata = seigr_file.metadata_manager.get_metadata()

        if use_cbor:
            try:
                serialized_data = cbor2.dumps(metadata)
                logger.debug("File serialized in CBOR format")
                return serialized_data
            except Exception as e:
                logger.error(f"CBOR serialization failed: {e}")
                raise ValueError(f"CBOR serialization error: {e}")
        else:
            try:
                seigr_file_proto = SeedDotSeigr()
                file_metadata_proto = FileMetadata(**metadata)
                seigr_file_proto.file_metadata.CopyFrom(file_metadata_proto)
                serialized_data = seigr_file_proto.SerializeToString()
                logger.debug("File serialized in Protobuf format")
                return serialized_data
            except Exception as e:
                logger.error(f"Protobuf serialization failed: {e}")
                raise ValueError(f"Protobuf serialization error: {e}")

    def load(self, file_path: str, use_cbor: bool = False) -> dict:
        """
        Deserializes a `.seigr` file from either CBOR or Protobuf format.

        Args:
            file_path (str): Path to the serialized file.
            use_cbor (bool): If True, interprets as CBOR format; otherwise, Protobuf.

        Returns:
            dict: Deserialized data as a dictionary.

        Raises:
            IOError: If file loading fails.
            ValueError: If deserialization fails due to incompatible data format.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            logger.info(f"Loaded serialized data from {file_path}")
            return self.deserialize(data, use_cbor)
        except IOError as e:
            logger.error(f"Failed to load serialized file from {file_path}: {e}")
            raise

    def deserialize(self, data: bytes, use_cbor: bool = False) -> dict:
        """
        Deserializes `.seigr` data from bytes, supporting CBOR and Protobuf.

        Args:
            data (bytes): The serialized data.
            use_cbor (bool): If True, interprets as CBOR format; otherwise, Protobuf.

        Returns:
            dict: Deserialized data as a dictionary.

        Raises:
            ValueError: If deserialization fails due to incompatible data format.
        """
        if use_cbor:
            try:
                deserialized_data = cbor2.loads(data)
                logger.debug("Data deserialized from CBOR format")
                return deserialized_data
            except Exception as e:
                logger.error(f"CBOR deserialization failed: {e}")
                raise ValueError(f"CBOR deserialization error: {e}")
        else:
            try:
                seigr_file_proto = SeedDotSeigr()
                seigr_file_proto.ParseFromString(data)
                deserialized_data = {
                    "file_metadata": {
                        "creator_id": seigr_file_proto.file_metadata.creator_id,
                        "file_hash": seigr_file_proto.file_metadata.file_hash,
                        "segment_count": seigr_file_proto.file_metadata.segment_count,
                        "created_at": seigr_file_proto.file_metadata.created_at,
                    },
                    "segments": [
                        {
                            "segment_index": segment.segment_index,
                            "segment_hash": segment.segment_hash,
                            "timestamp": segment.timestamp,
                        }
                        for segment in seigr_file_proto.segments
                    ],
                }
                logger.debug("Data deserialized from Protobuf format")
                return deserialized_data
            except Exception as e:
                logger.error(f"Protobuf deserialization failed: {e}")
                raise ValueError(f"Protobuf deserialization error: {e}")
