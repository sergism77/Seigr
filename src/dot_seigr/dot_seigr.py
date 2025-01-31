import os
from typing import Optional

from src.utils.timestamp_utils import get_current_protobuf_timestamp
from src.logger.secure_logger import secure_logger
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    SeedDotSeigr as SeedDotSeigrProto,
    AccessControlEntry,
    AccessControlList,
    OperationLog,
    PipelineStage,
    TriggerEvent,
)
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorSeverity  # ✅ Correct import
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from dot_seigr.capsule.seigr_link_manager import FileLinkManager
from dot_seigr.seigr_constants import HEADER_SIZE, MIN_REPLICATION, SEIGR_SIZE
from dot_seigr.seigr_file import SeigrFile


class DotSeigr:
    """
    Manages segmentation, linking, and metadata of Seigr data files.
    """

    def __init__(self, data: bytes, creator_id: str, file_type: str = "binary"):
        """
        Initializes a DotSeigr instance.

        Args:
            data (bytes): Binary data to be segmented.
            creator_id (str): Unique ID for the creator.
            file_type (str): Type of the file (default is "binary").
        """
        self.data = data
        self.creator_id = creator_id
        self.file_type = file_type
        self.version = "1.0"
        self.replication_count = MIN_REPLICATION
        self.link_manager = FileLinkManager()
        self.acl = AccessControlList(entries=[])
        self.pipeline_stages = []

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Correct Enum Usage
            category="Initialization",
            message=f"✅ DotSeigr instance initialized for {creator_id}.",
        )

    def create_segmented_seigr_files(
        self, directory: str, seed: SeedDotSeigrProto
    ) -> SeedDotSeigrProto:
        """
        Segments data, creates .seigr files, and saves them with metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigrProto): Seed protobuf structure.

        Returns:
            SeedDotSeigrProto: Updated seed.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE
        total_parts = (len(self.data) + segment_size - 1) // segment_size
        last_primary_hash = None

        os.makedirs(directory, exist_ok=True)

        for part_index in range(total_parts):
            try:
                primary_hash, file_path, secondary_link = self._create_and_save_segment(
                    directory, part_index, segment_size, last_primary_hash
                )
                last_primary_hash = primary_hash

                # ✅ Update seed with segment metadata
                seed_file_metadata = seed.segments.add()
                seed_file_metadata.segment_hash = primary_hash
                seed_file_metadata.timestamp.CopyFrom(get_current_protobuf_timestamp())

                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_INFO,
                    category="Segmentation",
                    message=f"✅ Segment {part_index} metadata added to seed.",
                )

            except Exception as e:
                secure_logger.log_audit_event(
                    severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
                    category="Segmentation",
                    message=f"❌ Segment {part_index} failed: {e}",
                )
                raise

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Segmentation",
            message="✅ All segments created successfully.",
        )
        return seed

    def _create_and_save_segment(
        self, directory: str, part_index: int, segment_size: int, last_primary_hash: Optional[str]
    ):
        """
        Creates and saves a single .seigr file segment.

        Args:
            directory (str): Directory to save the .seigr file.
            part_index (int): The segment index.
            segment_size (int): Size of each segment.
            last_primary_hash (Optional[str]): Hash of the previous segment.

        Returns:
            tuple: Primary hash, file path, and secondary link.
        """
        start = part_index * segment_size
        end = start + segment_size
        segment_data = self.data[start:end]

        hypha_crypt = HyphaCrypt(data=segment_data, segment_id=f"{self.creator_id}_{part_index}")
        primary_hash = hypha_crypt.compute_primary_hash()

        seigr_file = SeigrFile(
            data=segment_data,
            creator_id=self.creator_id,
            index=part_index,
            file_type=self.file_type,
        )

        if last_primary_hash:
            self.link_manager.set_links(last_primary_hash, [])

        seigr_file.set_links(
            primary_link=self.link_manager.get_links()["primary"],
            secondary_links=self.link_manager.get_links()["secondary"],
        )

        file_path = seigr_file.save_to_disk(directory)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="File Save",
            message=f"✅ Saved .seigr file part {part_index + 1} at {file_path}.",
        )

        secondary_link = hypha_crypt.compute_layered_hashes()
        self.link_manager.set_links(primary_hash, [secondary_link])

        self._record_operation_log(
            "create_segment", "system", f"Segment {part_index} created at {file_path}"
        )

        return primary_hash, file_path, secondary_link

    def add_acl_entry(self, user_id: str, role: str, permissions: str) -> None:
        """
        Adds an ACL entry for access control.

        Args:
            user_id (str): User ID.
            role (str): Role.
            permissions (str): Permissions.
        """
        entry = AccessControlEntry(user_id=user_id, role=role, permissions=permissions)
        self.acl.entries.append(entry)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="ACL",
            message=f"✅ Added ACL entry: {user_id} - {role}.",
        )

    def _record_operation_log(
        self, operation_type: str, performed_by: str, details: str = ""
    ) -> None:
        """
        Logs an operation.

        Args:
            operation_type (str): Type of operation.
            performed_by (str): Performer ID.
            details (str): Additional details.
        """
        log_entry = OperationLog(
            operation_type=operation_type,
            performed_by=performed_by,
            timestamp=get_current_protobuf_timestamp(),
            status="SUCCESS",
            details=details,
        )
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Operation Log",
            message=f"✅ Operation log recorded: {operation_type}.",
        )

    def save_seed_to_disk(self, seed: SeedDotSeigrProto, base_dir: str) -> str:
        """
        Saves the seed cluster.

        Args:
            seed (SeedDotSeigrProto): The seed.
            base_dir (str): Directory.

        Returns:
            str: File path.
        """
        filename = f"{self.creator_id}_seed_cluster.seigr"
        file_path = os.path.join(base_dir, filename)

        try:
            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(seed.SerializeToString())
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="File Save",
                message=f"✅ Seed cluster saved: {file_path}.",
            )
            return file_path
        except (IOError, ValueError) as e:
            secure_logger.log_audit_event(
                severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
                category="File Save",
                message=f"❌ Failed to save seed: {e}.",
            )
            raise
