import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    SeedDotSeigr as SeedDotSeigrProto,
    AccessControlList,
    AccessControlEntry,
    PipelineStage,
    TriggerEvent,
    OperationLog
)
from dot_seigr.capsule.seigr_link_manager import FileLinkManager

# Setup logging
logger = logging.getLogger(__name__)

class DotSeigr:
    def __init__(self, data: bytes, creator_id: str, file_type: str = "binary"):
        """
        Initializes a DotSeigr instance for creating and managing .seigr files with multidimensional links.

        Args:
            data (bytes): Binary data to be segmented and saved.
            creator_id (str): Unique ID for the creator.
            file_type (str): Type of the file (default is "binary").
        """
        self.data = data
        self.creator_id = creator_id
        self.file_type = file_type
        self.version = "1.0"
        self.replication_count = MIN_REPLICATION
        self.link_manager = FileLinkManager()  # Corrected to FileLinkManager
        self.acl = AccessControlList(entries=[])  # Access control list
        self.pipeline_stages = []  # Event-triggered pipeline stages

    def create_segmented_seigr_files(self, directory: str, seed: SeedDotSeigrProto) -> SeedDotSeigrProto:
        """
        Segments data, creates .seigr files, and saves them with protocol-compliant Protobuf metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigrProto): Seed protobuf structure for managing the cluster.

        Returns:
            SeedDotSeigrProto: Updated seed with added .seigr files.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE  # Calculate usable segment size
        total_parts = (len(self.data) + segment_size - 1) // segment_size
        last_primary_hash = None  # Track previous primary hash for linking

        # Ensure directory exists
        os.makedirs(directory, exist_ok=True)

        for part_index in range(total_parts):
            try:
                primary_hash, file_path, secondary_link = self._create_and_save_segment(
                    directory, part_index, segment_size, last_primary_hash
                )
                last_primary_hash = primary_hash  # Update for chaining

                # Update seed with segment metadata
                seed_file_metadata = seed.segments.add()
                seed_file_metadata.segment_hash = primary_hash
                seed_file_metadata.timestamp = datetime.now(timezone.utc).isoformat()

                logger.debug(f"Hash tree and secondary links added for segment {part_index}.")

            except Exception as e:
                logger.error(f"Failed to create and save segment {part_index}: {e}")
                raise

        logger.info("All segments created and saved successfully.")
        return seed

    def _create_and_save_segment(self, directory: str, part_index: int, segment_size: int, last_primary_hash: str):
        """
        Creates and saves a single .seigr file segment.

        Args:
            directory (str): Directory to save the .seigr file.
            part_index (int): The segment index.
            segment_size (int): Size of each segment.
            last_primary_hash (str): Hash of the previous segment for linking.

        Returns:
            tuple: Primary hash, file path, and secondary link for the segment.
        """
        start = part_index * segment_size
        end = start + segment_size
        segment_data = self.data[start:end]

        # Initialize HyphaCrypt and compute primary hash
        hypha_crypt = HyphaCrypt(data=segment_data, segment_id=f"{self.creator_id}_{part_index}")
        primary_hash = hypha_crypt.compute_primary_hash()

        # Create SeigrFile instance
        seigr_file = SeigrFile(
            data=segment_data,
            creator_id=self.creator_id,
            index=part_index,
            file_type=self.file_type
        )

        # Configure links
        if last_primary_hash:
            self.link_manager.set_links(last_primary_hash, [])  # Use last hash as primary link
        seigr_file.set_links(
            primary_link=self.link_manager.get_links()["primary"],
            secondary_links=self.link_manager.get_links()["secondary"]
        )

        # Save the segment and log its path
        file_path = seigr_file.save_to_disk(directory)
        logger.info(f"Saved .seigr file part {part_index + 1} at {file_path}")

        # Compute secondary link for adaptive retrieval
        secondary_link = hypha_crypt.compute_layered_hashes()
        self.link_manager.set_links(primary_hash, [secondary_link])

        # Record operation log
        self._record_operation_log("create_segment", "system", f"Segment {part_index} created at {file_path}")

        return primary_hash, file_path, secondary_link

    def add_acl_entry(self, user_id: str, role: str, permissions: str):
        """
        Adds an entry to the access control list for role-based access.
        """
        entry = AccessControlEntry(user_id=user_id, role=role, permissions=permissions)
        self.acl.entries.append(entry)
        logger.info(f"Added ACL entry for user: {user_id} with role: {role} and permissions: {permissions}")

    def add_pipeline_stage(self, stage_name: str, operation_type: str, trigger_event: TriggerEvent):
        """
        Adds a pipeline stage with a specified trigger event.
        
        Args:
            stage_name (str): Name of the pipeline stage.
            operation_type (str): Type of operation for the stage.
            trigger_event (TriggerEvent): Event that triggers this stage.
        """
        stage = PipelineStage(
            stage_name=stage_name,
            operation_type=operation_type,
            trigger_event=trigger_event
        )
        self.pipeline_stages.append(stage)
        logger.debug(f"Added pipeline stage: {stage_name} triggered by {trigger_event}")

    def _record_operation_log(self, operation_type: str, performed_by: str, details=""):
        """
        Logs an operation in the system for tracking purposes.
        
        Args:
            operation_type (str): The type of operation (e.g., "access", "update").
            performed_by (str): Identifier of the performer.
            details (str): Additional details for context.
        """
        log_entry = OperationLog(
            operation_type=operation_type,
            performed_by=performed_by,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="SUCCESS",
            details=details
        )
        logger.info(f"Operation log recorded: {operation_type} by {performed_by}")

    def save_seed_to_disk(self, seed: SeedDotSeigrProto, base_dir: str) -> str:
        """
        Saves the seed cluster as a protobuf binary file.

        Args:
            seed (SeedDotSeigrProto): The seed protobuf structure.
            base_dir (str): Directory to save the seed file.

        Returns:
            str: Path to the saved seed file.
        """
        filename = f"{self.creator_id}_seed_cluster.seigr"
        file_path = os.path.join(base_dir, filename)

        try:
            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(seed.SerializeToString())
            logger.info(f"Seed cluster saved successfully at {file_path}")
            return file_path
        except (IOError, ValueError) as e:
            logger.error(f"Failed to save seed cluster at {file_path}: {e}")
            raise
