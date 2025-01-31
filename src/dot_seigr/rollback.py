from datetime import datetime, timezone
from typing import Optional

from dot_seigr.capsule.seigr_integrity import (
    validate_acl_for_integrity_check,
    verify_layer_integrity,
)
from dot_seigr.seigr_file import SeigrFile
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    TemporalLayer,
    TriggerEvent,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Seigr Alert Levels


def rollback_to_previous_state(
    seigr_file: SeigrFile, user_id: str, event: Optional[TriggerEvent] = None
) -> bool:
    """
    Reverts a segment to its previous secure state using temporal layers, ensuring integrity before applying rollback.

    Args:
        seigr_file (SeigrFile): The segment to roll back.
        user_id (str): ID of the user requesting the rollback.
        event (Optional[TriggerEvent]): The event that triggered the rollback, if any.

    Returns:
        bool: True if rollback was successful, False otherwise.
    """
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Rollback",
        message=f"Rollback initiated for {seigr_file.hash} by {user_id}",
    )

    # Step 1: ACL Verification
    if not validate_acl_for_integrity_check(seigr_file.acl, user_id):
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_WARNING,
            category="Rollback",
            message=f"User {user_id} lacks rollback permissions for {seigr_file.hash}.",
        )
        return False

    # Step 2: Check rollback availability
    if not verify_rollback_availability(seigr_file):
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_WARNING,
            category="Rollback",
            message=f"No previous layers available for rollback of {seigr_file.hash}.",
        )
        return False

    # Step 3: Access the second-to-last temporal layer
    previous_layer = seigr_file.temporal_layers[-2]

    # Step 4: Verify integrity of the previous state
    expected_hash = previous_layer.layer_hash
    if not verify_layer_integrity(previous_layer, expected_hash):
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_ERROR,
            category="Rollback",
            message=f"Integrity verification failed for {previous_layer.timestamp}. Rollback aborted.",
        )
        return False

    # Step 5: Log the rollback attempt
    log_rollback_attempt(seigr_file.hash, previous_layer.timestamp, user_id, event)

    # Step 6: Revert segment data and metadata
    try:
        revert_segment_data(seigr_file, previous_layer)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Rollback",
            message=f"Reverted {seigr_file.hash} to {previous_layer.timestamp}.",
        )
    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_ERROR,
            category="Rollback",
            message=f"Error during rollback: {e}",
        )
        return False

    # Step 7: Log successful rollback
    log_rollback_success(seigr_file.hash, previous_layer.timestamp, user_id)
    return True


def verify_rollback_availability(seigr_file: SeigrFile) -> bool:
    """Checks if a previous temporal layer exists for rollback."""
    return len(seigr_file.temporal_layers) > 1


def revert_segment_data(seigr_file: SeigrFile, previous_layer: TemporalLayer) -> None:
    """Reverts the current segment's data and metadata to a previous secure state."""
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
        category="Rollback",
        message=f"Reverting {seigr_file.hash} to previous state.",
    )

    seigr_file.data = previous_layer.data_snapshot["data"]
    seigr_file.hash = (
        previous_layer.layer_hash.decode()
        if isinstance(previous_layer.layer_hash, bytes)
        else previous_layer.layer_hash
    )

    # Restore metadata and links
    restore_metadata_links(seigr_file, previous_layer)
    restore_coordinate_index(seigr_file, previous_layer)

    # Add a new temporal layer to document this rollback
    seigr_file.add_temporal_layer()

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Rollback",
        message=f"Rollback completed for {seigr_file.hash}.",
    )


def restore_metadata_links(seigr_file: SeigrFile, previous_layer: TemporalLayer) -> None:
    """Restores primary and secondary links from a previous secure state."""
    primary_link = previous_layer.data_snapshot.get("primary_link", b"")
    seigr_file.metadata.primary_link = (
        primary_link.decode("utf-8") if isinstance(primary_link, bytes) else primary_link
    )

    # Restore secondary links
    seigr_file.metadata.secondary_links.clear()
    for link in previous_layer.data_snapshot.get("secondary_links", []):
        seigr_file.metadata.secondary_links.append(
            link.decode("utf-8") if isinstance(link, bytes) else link
        )

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
        category="Rollback",
        message=f"Restored metadata links for {seigr_file.hash}.",
    )


def restore_coordinate_index(seigr_file: SeigrFile, previous_layer: TemporalLayer) -> None:
    """Restores the coordinate index from a previous secure state."""
    if "coordinate_index" in previous_layer.data_snapshot:
        coordinate_data = previous_layer.data_snapshot["coordinate_index"]
        seigr_file.metadata.coordinate_index.ParseFromString(coordinate_data)

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
        category="Rollback",
        message=f"Coordinate index restored for {seigr_file.hash}.",
    )


def log_rollback_attempt(
    segment_hash: str, rollback_timestamp: str, user_id: str, event: Optional[TriggerEvent] = None
) -> None:
    """Logs a rollback attempt for auditing purposes."""
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Rollback",
        message=f"Rollback attempt: {segment_hash} to {rollback_timestamp} by {user_id}. Trigger: {event.name if event else 'Manual'}",
    )


def log_rollback_success(segment_hash: str, rollback_timestamp: str, user_id: str) -> None:
    """Logs a successful rollback event for auditing."""
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Rollback",
        message=f"Rollback successful: {segment_hash} reverted to {rollback_timestamp} by {user_id}.",
    )
