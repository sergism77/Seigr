import os
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    SeedDotSeigr as SeedDotSeigrProto, PipelineStage, TriggerEvent, OperationLog, AccessControlList, AccessControlEntry
)
from src.crypto.hash_utils import hypha_hash
from .seigr_constants import HEADER_SIZE, SEIGR_SIZE

# Constants
CLUSTER_LIMIT = SEIGR_SIZE - HEADER_SIZE  # Max size for primary cluster

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeedDotSeigr:
    """
    Manages Seigr clusters by indexing and organizing segments in primary and secondary clusters,
    adding access control entries, pipeline stages, and verifying cluster integrity.
    """

    def __init__(self, root_hash: str):
        """
        Initializes SeedDotSeigr as the central seed for indexing and management.
        
        Args:
            root_hash (str): Root hash for the seed file's primary identifier.
        """
        self.root_hash = root_hash
        self.seed_hash = hypha_hash(root_hash.encode())  # Unique hash for network ID
        self.cluster = SeedDotSeigrProto()
        self.cluster.root_hash = self.root_hash
        self.cluster.seed_hash = self.seed_hash
        self.secondary_cluster_active = False
        self.acl = AccessControlList(entries=[])
        self.pipeline_stages = []
        self.integrity_checksum = None
        self._compute_integrity_checksum()
        logger.debug(f"Initialized SeedDotSeigr with root hash {self.root_hash} and seed hash {self.seed_hash}")

    def _compute_integrity_checksum(self) -> None:
        """
        Computes an integrity checksum for the cluster and updates the cluster metadata.
        """
        integrity_data = f"{self.cluster.root_hash}{self.cluster.seed_hash}".encode('utf-8')
        self.integrity_checksum = hypha_hash(integrity_data)
        self.cluster.integrity_checksum = self.integrity_checksum
        logger.debug(f"Computed integrity checksum: {self.integrity_checksum}")

    def add_acl_entry(self, user_id: str, role: str, permissions: str) -> None:
        """
        Adds an entry to the access control list for role-based access.

        Args:
            user_id (str): User or node ID.
            role (str): Role assigned to the user.
            permissions (str): Permissions associated with the role.
        """
        entry = AccessControlEntry(user_id=user_id, role=role, permissions=permissions)
        self.acl.entries.append(entry)
        logger.info(f"Added ACL entry for user: {user_id} with role: {role} and permissions: {permissions}")

    def add_pipeline_stage(self, stage_name: str, operation_type: str, trigger_event: TriggerEvent) -> None:
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

    def add_segment(self, segment_hash: str, index: int, threat_level: int = 0) -> None:
        """
        Adds a segment to the primary cluster or creates a new cluster if the limit is reached.
        
        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Segment index.
            threat_level (int): Threat level for adaptive replication.
        """
        if self._is_primary_cluster_full():
            logger.warning(f"Primary cluster limit reached, creating a new secondary cluster for segment {segment_hash}.")
            self._create_new_cluster(segment_hash, index, threat_level)
        else:
            self._add_segment_to_cluster(segment_hash, index, threat_level)
            self._record_operation_log("add_segment", "system", f"Segment {segment_hash} added at index {index}")
            logger.info(f"Added segment {segment_hash} (Index {index}, Threat Level {threat_level}) to primary cluster.")

    def _is_primary_cluster_full(self) -> bool:
        """
        Checks if the primary cluster has reached its segment storage limit.

        Returns:
            bool: True if primary cluster is full, otherwise False.
        """
        current_size = len(self.cluster.segments) * HEADER_SIZE
        return current_size >= CLUSTER_LIMIT

    def _create_new_cluster(self, segment_hash: str, index: int, threat_level: int = 0) -> None:
        """
        Creates a new secondary cluster for segments beyond primary capacity.
        
        Args:
            segment_hash (str): Segment hash initiating new cluster.
            index (int): Segment index.
            threat_level (int): Threat level for adaptive replication.
        """
        secondary_cluster = SeedDotSeigr(self.root_hash)
        secondary_cluster.add_segment(segment_hash, index, threat_level)
        secondary_cluster_path = secondary_cluster.save_to_disk("clusters")

        # Track secondary cluster status and paths
        self.cluster.secondary_clusters.append(secondary_cluster_path)
        self.secondary_cluster_active = True
        logger.info(f"Created secondary cluster with seed hash {secondary_cluster.seed_hash}")

    def _add_segment_to_cluster(self, segment_hash: str, index: int, threat_level: int) -> None:
        """
        Adds a segment to the current primary cluster.

        Args:
            segment_hash (str): The hash of the segment to add.
            index (int): Segment index within the file.
            threat_level (int): Threat level for adaptive replication.
        """
        segment = self.cluster.segments.add()
        segment.segment_index = index
        segment.segment_hash = segment_hash
        segment.threat_level = threat_level
        logger.debug(f"Segment added to cluster with hash {segment_hash} at index {index}")

    def _record_operation_log(self, operation_type: str, performed_by: str, details: str = "") -> None:
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
        self.cluster.operation_logs.append(log_entry)
        logger.info(f"Operation log recorded: {operation_type} by {performed_by}")

    def save_to_disk(self, directory: str) -> str:
        """
        Serializes the seed data and saves it to disk.
        
        Args:
            directory (str): Directory for storing the seed file.

        Returns:
            str: File path of saved seed file.
        """
        seed_filename = f"{self.seed_hash}.seed_seigr.pb"
        seed_file_path = os.path.join(directory, seed_filename)
        os.makedirs(directory, exist_ok=True)

        try:
            with open(seed_file_path, "wb") as f:
                f.write(self.cluster.SerializeToString())
            logger.info(f"Seed cluster file saved at {seed_file_path}")
            return seed_file_path
        except IOError as e:
            logger.error(f"Failed to save seed cluster file: {e}")
            raise

    def load_from_disk(self, file_path: str) -> None:
        """
        Deserializes and loads cluster data from a Protobuf file.
        
        Args:
            file_path (str): Path to the saved seed file.
        """
        try:
            with open(file_path, "rb") as f:
                self.cluster.ParseFromString(f.read())
            logger.info(f"Loaded cluster data from {file_path}")
        except IOError as e:
            logger.error(f"Failed to load cluster data: {e}")
            raise

    def ping_network(self) -> None:
        """
        Sends a ping to update active time and connectivity for this seed file.
        """
        timestamp = int(time.time())
        self.cluster.last_ping = timestamp
        logger.info(f"Ping sent at {timestamp}")
