import os
import time
from datetime import datetime, timezone

from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    AccessControlEntry,
    AccessControlList,
    OperationLog,
    PipelineStage,
    TriggerEvent,
    SeedDotSeigr as SeedDotSeigrProto,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Seigr Alert Levels
from .seigr_constants import HEADER_SIZE, SEIGR_SIZE

# Constants
CLUSTER_LIMIT = SEIGR_SIZE - HEADER_SIZE  # Maximum primary cluster size


class SeedDotSeigr:
    """
    Manages Seigr clusters by indexing and organizing segments in primary and secondary clusters.
    """

    def __init__(self, root_hash: str):
        """
        Initializes SeedDotSeigr as the central seed for indexing and management.

        Args:
            root_hash (str): Root hash for the seed file’s primary identifier.
        """
        self.root_hash = root_hash
        hypha_crypt = HyphaCrypt(root_hash.encode(), segment_id="seed")
        self.seed_hash = hypha_crypt.hypha_hash_wrapper(root_hash.encode())
        self.cluster = SeedDotSeigrProto()
        self.cluster.root_hash = self.root_hash
        self.cluster.seed_hash = self.seed_hash
        self.secondary_cluster_active = False
        self.acl = AccessControlList(entries=[])
        self.pipeline_stages = []
        self.integrity_checksum = None

        self._compute_integrity_checksum()
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeedDotSeigr",
            message=f"SeedDotSeigr initialized with root hash {self.root_hash}",
        )

    def _compute_integrity_checksum(self) -> None:
        """
        Computes an integrity checksum for the cluster and updates the cluster metadata.
        Ensures redundancy avoidance.
        """
        integrity_data = f"{self.cluster.root_hash}{self.cluster.seed_hash}".encode("utf-8")
        hypha_crypt_integrity = HyphaCrypt(integrity_data, segment_id="seed_integrity")
        new_checksum = hypha_crypt_integrity.hypha_hash_wrapper(integrity_data)

        if new_checksum != self.integrity_checksum:  # Avoid unnecessary updates
            self.integrity_checksum = new_checksum
            self.cluster.integrity_checksum = self.integrity_checksum
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
                category="SeedDotSeigr",
                message=f"Integrity checksum updated: {self.integrity_checksum}",
            )

    def add_acl_entry(self, user_id: str, role: str, permissions: str) -> None:
        """
        Adds an ACL entry for role-based access.

        Args:
            user_id (str): User or node ID.
            role (str): Role assigned.
            permissions (str): Permissions assigned.
        """
        entry = AccessControlEntry(user_id=user_id, role=role, permissions=permissions)
        self.acl.entries.append(entry)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeedDotSeigr",
            message=f"ACL entry added: {user_id} - Role: {role}",
        )

    def add_pipeline_stage(
        self, stage_name: str, operation_type: str, trigger_event: TriggerEvent
    ) -> None:
        """
        Adds a pipeline stage.

        Args:
            stage_name (str): Name of the pipeline stage.
            operation_type (str): Type of operation.
            trigger_event (TriggerEvent): Event that triggers it.
        """
        stage = PipelineStage(
            stage_name=stage_name, operation_type=operation_type, trigger_event=trigger_event
        )
        self.pipeline_stages.append(stage)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
            category="SeedDotSeigr",
            message=f"Pipeline stage added: {stage_name}",
        )

    def add_segment(self, segment_hash: str, index: int, threat_level: int = 0) -> None:
        """
        Adds a segment to the primary cluster or creates a secondary cluster if the limit is reached.

        Args:
            segment_hash (str): Unique segment hash.
            index (int): Segment index.
            threat_level (int): Threat level for adaptive replication.
        """
        if self._is_primary_cluster_full():
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="SeedDotSeigr",
                message=f"Primary cluster full. Creating secondary cluster for {segment_hash}.",
            )
            self._create_new_cluster(segment_hash, index, threat_level)
        else:
            self._add_segment_to_cluster(segment_hash, index, threat_level)
            self._record_operation_log(
                "add_segment", "system", f"Segment {segment_hash} added at index {index}"
            )

    def _is_primary_cluster_full(self) -> bool:
        """Checks if the primary cluster has reached its storage limit."""
        return len(self.cluster.segments) * HEADER_SIZE >= CLUSTER_LIMIT

    def _create_new_cluster(self, segment_hash: str, index: int, threat_level: int = 0) -> None:
        """Creates a new secondary cluster."""
        secondary_cluster = SeedDotSeigr(self.root_hash)
        secondary_cluster.add_segment(segment_hash, index, threat_level)
        secondary_cluster_path = secondary_cluster.save_to_disk("clusters")

        self.cluster.secondary_clusters.append(secondary_cluster_path)
        self.secondary_cluster_active = True
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeedDotSeigr",
            message=f"New secondary cluster created: {secondary_cluster.seed_hash}.",
        )

    def _add_segment_to_cluster(self, segment_hash: str, index: int, threat_level: int) -> None:
        """Adds a segment to the current primary cluster."""
        segment = self.cluster.segments.add()
        segment.segment_index = index
        segment.segment_hash = segment_hash
        segment.threat_level = threat_level
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
            category="SeedDotSeigr",
            message=f"Segment {segment_hash} added to cluster at index {index}.",
        )

    def _record_operation_log(
        self, operation_type: str, performed_by: str, details: str = ""
    ) -> None:
        """Logs an operation in the system for tracking and auditing."""
        log_entry = OperationLog(
            operation_type=operation_type,
            performed_by=performed_by,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="SUCCESS",
            details=details,
        )
        self.cluster.operation_logs.append(log_entry)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeedDotSeigr",
            message=f"Operation logged: {operation_type} by {performed_by}. Details: {details}",
        )

    def save_to_disk(self, directory: str) -> str:
        """Saves the seed cluster to disk."""
        seed_filename = f"{self.seed_hash}.seed_seigr.pb"
        seed_file_path = os.path.join(directory, seed_filename)
        os.makedirs(directory, exist_ok=True)

        try:
            with open(seed_file_path, "wb") as f:
                f.write(self.cluster.SerializeToString())
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="SeedDotSeigr",
                message=f"Seed cluster saved at {seed_file_path}.",
            )
            return seed_file_path
        except IOError as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="SeedDotSeigr",
                message=f"Failed to save seed cluster: {e}",
            )
            raise

    def load_from_disk(self, file_path: str) -> None:
        """Loads cluster data from a Protobuf file."""
        try:
            with open(file_path, "rb") as f:
                self.cluster.ParseFromString(f.read())
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="SeedDotSeigr",
                message=f"Loaded cluster data from {file_path}.",
            )
        except (IOError, ValueError) as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_ERROR,
                category="SeedDotSeigr",
                message=f"Failed to load cluster: {e}",
            )
            raise
