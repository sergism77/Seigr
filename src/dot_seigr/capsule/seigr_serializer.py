import os
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.integrity_verification import _get_hypha_crypt
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.file_metadata_pb2 import FileMetadata, SegmentMetadata


class CapsuleSerializer:
    """
    Handles serialization and deserialization of Seigr capsule data, including methods
    to save, load, and verify capsule metadata and segment contents.
    """

    def save_capsule(self, capsule_data, base_dir: str, filename: str) -> str:
        """
        Serializes and saves capsule data to disk in a specified directory.

        Args:
            capsule_data (FileMetadata or SegmentMetadata): The data to be serialized.
            base_dir (str): Directory to save the capsule file.
            filename (str): Filename for the saved capsule.

        Returns:
            str: The full path to the saved capsule file.
        """
        file_path = os.path.join(base_dir, filename)
        os.makedirs(base_dir, exist_ok=True)

        try:
            with open(file_path, "wb") as file:
                file.write(capsule_data.SerializeToString())

            secure_logger.log_audit_event(
                "info", "CapsuleSerializer", f"Capsule saved successfully at {file_path}."
            )
            return file_path
        except IOError as e:
            secure_logger.log_audit_event(
                "error", "CapsuleSerializer", f"Failed to save capsule at {file_path}: {e}."
            )
            raise

    def load_capsule(self, file_path: str, capsule_type) -> FileMetadata:
        """
        Loads and deserializes capsule data from a file.

        Args:
            file_path (str): Path to the capsule file to load.
            capsule_type: Protobuf message type, either FileMetadata or SegmentMetadata.

        Returns:
            FileMetadata: Capsule data deserialized from the file.
        """
        capsule_data = capsule_type()
        try:
            with open(file_path, "rb") as file:
                capsule_data.ParseFromString(file.read())

            secure_logger.log_audit_event(
                "info", "CapsuleSerializer", f"Capsule loaded successfully from {file_path}."
            )
            return capsule_data
        except (IOError, ValueError) as e:
            secure_logger.log_audit_event(
                "error", "CapsuleSerializer", f"Failed to load capsule from {file_path}: {e}."
            )
            raise

    def save_segment_metadata(self, segment_metadata: SegmentMetadata, base_dir: str) -> str:
        """
        Saves metadata for an individual segment, serialized into a .segm file.

        Args:
            segment_metadata (SegmentMetadata): Metadata for the segment to be saved.
            base_dir (str): Directory to save the segment metadata file.

        Returns:
            str: Path to the saved segment metadata file.
        """
        filename = f"{segment_metadata.segment_hash}.segm"
        return self.save_capsule(segment_metadata, base_dir, filename)

    def load_segment_metadata(self, file_path: str) -> SegmentMetadata:
        """
        Loads segment metadata from a .segm file.

        Args:
            file_path (str): Path to the segment metadata file.

        Returns:
            SegmentMetadata: Deserialized SegmentMetadata object.
        """
        return self.load_capsule(file_path, SegmentMetadata)

    def verify_file_integrity(self, file_metadata: FileMetadata, base_dir: str) -> bool:
        """
        Verifies the integrity of all segments listed in the file metadata.

        Args:
            file_metadata (FileMetadata): File metadata containing segment hashes.
            base_dir (str): Directory where the segments are stored.

        Returns:
            bool: True if all segment hashes match, False otherwise.
        """
        all_segments_valid = True

        for segment in file_metadata.segments:
            segment_path = os.path.join(base_dir, f"{segment.segment_hash}.segm")
            try:
                loaded_segment = self.load_segment_metadata(segment_path)
                HyphaCrypt = _get_hypha_crypt()

                # ✅ Fix: Ensure capsule_data is properly assigned before use
                capsule_data = loaded_segment  # Assign from loaded segment metadata

                if capsule_data is None:
                    raise ValueError("capsule_data is not initialized before encryption.")

                hypha_crypt = HyphaCrypt(capsule_data.SerializeToString(), segment_id="serializer")
                computed_hash = hypha_crypt.HASH_SEIGR_SENARY(capsule_data.SerializeToString())

                if computed_hash != segment.segment_hash:
                    secure_logger.log_audit_event(
                        "warning",
                        "CapsuleSerializer",
                        f"Integrity check failed for segment {segment.segment_hash}.",
                    )
                    all_segments_valid = False
                else:
                    secure_logger.log_audit_event(
                        "debug",
                        "CapsuleSerializer",
                        f"Segment {segment.segment_hash} verified successfully.",
                    )

            except (FileNotFoundError, ValueError) as e:
                secure_logger.log_audit_event(
                    "error",
                    "CapsuleSerializer",
                    f"Failed to verify segment at {segment_path}: {e}.",
                )
                all_segments_valid = False

        if all_segments_valid:
            secure_logger.log_audit_event(
                "info", "CapsuleSerializer", "All segments passed integrity check."
            )
        else:
            secure_logger.log_audit_event(
                "warning", "CapsuleSerializer", "One or more segments failed integrity check."
            )

        return all_segments_valid

    def verify_capsule_integrity(self, capsule_data: FileMetadata, expected_hash: str) -> bool:
        """
        Verifies the integrity of a single capsule by comparing the expected hash with the computed hash.

        Args:
            capsule_data (FileMetadata or SegmentMetadata): The Protobuf message to verify.
            expected_hash (str): The expected hash to verify against.

        Returns:
            bool: True if the integrity check passes, False otherwise.
        """
        hypha_crypt = HyphaCrypt(capsule_data.SerializeToString(), segment_id="serializer")
        computed_hash = hypha_crypt.HASH_SEIGR_SENARY(capsule_data.SerializeToString())

        if computed_hash == expected_hash:
            secure_logger.log_audit_event(
                "debug",
                "CapsuleSerializer",
                f"Capsule integrity verified successfully. Hash: {computed_hash}.",
            )
            return True
        else:
            secure_logger.log_audit_event(
                "warning",
                "CapsuleSerializer",
                f"Capsule integrity check failed. Expected: {expected_hash}, Got: {computed_hash}.",
            )
            return False
