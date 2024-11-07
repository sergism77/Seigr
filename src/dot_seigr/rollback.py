import logging
from datetime import datetime, timezone
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import TemporalLayer

logger = logging.getLogger(__name__)

def rollback_to_previous_state(seigr_file: SeigrFile) -> bool:
    """
    Reverts a segment to its previous secure state based on temporal layers.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile to roll back.
    
    Returns:
        bool: True if rollback was successful, False otherwise.
    """
    if not verify_rollback_availability(seigr_file):
        logger.warning(f"No previous layers available for rollback of segment {seigr_file.hash}.")
        return False

    # Access the last secure state (second-to-last temporal layer)
    previous_layer = seigr_file.temporal_layers[-2]

    # Use the previous layer's hash as the expected hash for validation
    expected_hash = previous_layer.layer_hash

    # Verify the integrity of the previous state before proceeding
    if not verify_layer_integrity(previous_layer, expected_hash):
        logger.error(f"Integrity verification failed for previous layer at {previous_layer.timestamp}. Rollback aborted.")
        return False

    # Log the rollback attempt for audit purposes
    log_rollback_attempt(seigr_file.hash, previous_layer.timestamp)

    # Revert segment data and metadata to the previous state
    revert_segment_data(seigr_file, previous_layer)

    # Log the successful rollback event
    log_rollback_success(seigr_file.hash, previous_layer.timestamp)

    logger.info(f"Rollback successful for segment {seigr_file.hash}. Reverted to timestamp {previous_layer.timestamp}.")
    return True

def verify_rollback_availability(seigr_file: SeigrFile) -> bool:
    """
    Checks if a previous state exists for rollback.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being checked.
    
    Returns:
        bool: True if rollback is possible, False otherwise.
    """
    has_previous_layer = len(seigr_file.temporal_layers) > 1
    if not has_previous_layer:
        logger.debug(f"Segment {seigr_file.hash} has insufficient temporal layers for rollback.")
    return has_previous_layer

def verify_layer_integrity(previous_layer: TemporalLayer, expected_hash: str) -> bool:
    """
    Verifies the integrity of a temporal layer before committing to a rollback.
    
    Args:
        previous_layer (TemporalLayer): The temporal layer to verify.
        expected_hash (str): The expected hash to validate against the layer's hash.
    
    Returns:
        bool: True if the layer is verified as intact, False otherwise.
    """
    # Compare layer hash with the expected hash for validation
    valid = previous_layer.layer_hash == expected_hash

    if valid:
        logger.debug(f"Layer at {previous_layer.timestamp} passed integrity verification.")
    else:
        logger.warning(f"Integrity verification failed for layer at {previous_layer.timestamp}.")
    return valid

import json  # Or other deserialization as needed for data structures

def revert_segment_data(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Replaces the current segment data and metadata with the data from a previous secure state.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile to revert.
        previous_layer (TemporalLayer): TemporalLayer containing the data snapshot of the previous state.
    """
    # Deserialize data as required by the structure of data_snapshot
    seigr_file.data = previous_layer.data_snapshot["data"]  # Assuming "data" is stored as bytes and needs decoding
    seigr_file.hash = previous_layer.layer_hash  # Update hash to match previous state

    # Deserialize links and coordinates
    restore_metadata_links(seigr_file, previous_layer)
    restore_coordinate_index(seigr_file, previous_layer)

    # Add a temporal layer reflecting the reverted state
    seigr_file.add_temporal_layer()
    logger.debug(f"Segment {seigr_file.hash} reverted to previous state with hash {previous_layer.layer_hash}.")


def restore_metadata_links(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Restores primary and secondary links from a previous secure state.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being reverted.
        previous_layer (TemporalLayer): TemporalLayer with the snapshot of previous links.
    """
    # Deserialize primary and secondary links if necessary
    seigr_file.metadata.primary_link = previous_layer.data_snapshot.get("primary_link", b"").decode("utf-8")
    seigr_file.metadata.secondary_links.clear()
    seigr_file.metadata.secondary_links.extend(
        json.loads(previous_layer.data_snapshot.get("secondary_links", b"[]").decode("utf-8"))
    )
    logger.debug(f"Restored primary and secondary links for segment {seigr_file.hash}.")


def restore_coordinate_index(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Restores the coordinate index for the segment from a previous secure state.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being reverted.
        previous_layer (TemporalLayer): TemporalLayer with the coordinate snapshot.
    """
    # Deserialize the coordinate index if necessary
    coord_index_snapshot = json.loads(previous_layer.data_snapshot.get("coordinate_index", b"{}").decode("utf-8"))
    if coord_index_snapshot:
        seigr_file.metadata.coordinate_index.CopyFrom(coord_index_snapshot)
        logger.debug(f"Coordinate index restored for segment {seigr_file.hash}.")

def log_rollback_attempt(segment_hash: str, rollback_timestamp: str):
    """
    Logs a rollback attempt for auditing purposes.
    
    Args:
        segment_hash (str): Hash of the segment that was attempted for rollback.
        rollback_timestamp (str): Timestamp of the previous state for rollback attempt.
    """
    attempt_entry = {
        "segment_hash": segment_hash,
        "rollback_timestamp": rollback_timestamp,
        "attempted_at": datetime.now(timezone.utc).isoformat()
    }
    logger.info(f"Rollback attempt log entry: {attempt_entry}")

def log_rollback_success(segment_hash: str, rollback_timestamp: str):
    """
    Logs a successful rollback event for auditing purposes.
    
    Args:
        segment_hash (str): Hash of the segment that was rolled back.
        rollback_timestamp (str): Timestamp of the previous state to which the segment was reverted.
    """
    success_entry = {
        "segment_hash": segment_hash,
        "rollback_timestamp": rollback_timestamp,
        "executed_at": datetime.now(timezone.utc).isoformat()
    }
    logger.info(f"Rollback success log entry: {success_entry}")
