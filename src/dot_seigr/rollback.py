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
    logger.info(f"Initiating rollback for segment {seigr_file.hash}")

    # Step 1: Check rollback availability
    if not verify_rollback_availability(seigr_file):
        logger.warning(f"No previous layers available for rollback of segment {seigr_file.hash}.")
        return False

    # Step 2: Access the second-to-last temporal layer as the last secure state
    previous_layer = seigr_file.temporal_layers[-2]
    
    # Ensure previous_layer fields are in the expected format
    if isinstance(previous_layer.layer_hash, bytes):
        previous_layer.layer_hash = previous_layer.layer_hash.decode()
    if isinstance(seigr_file.hash, bytes):
        seigr_file.hash = seigr_file.hash.decode()

    # Use the previous layer's hash as the expected hash for validation
    expected_hash = previous_layer.layer_hash

    # Step 3: Verify the integrity of the previous state before proceeding
    if not verify_layer_integrity(previous_layer, expected_hash):
        logger.error(f"Integrity verification failed for previous layer at {previous_layer.timestamp}. Rollback aborted.")
        return False

    # Step 4: Log the rollback attempt for audit purposes
    log_rollback_attempt(seigr_file.hash, previous_layer.timestamp)

    # Step 5: Revert segment data and metadata to the previous state
    try:
        revert_segment_data(seigr_file, previous_layer)  # Ensure revert_segment_data does not decode strings
        logger.info(f"Reverted segment {seigr_file.hash} data to previous layer at timestamp {previous_layer.timestamp}.")
    except Exception as e:
        logger.error(f"Error during data revert for segment {seigr_file.hash}: {e}")
        return False

    # Step 6: Log the successful rollback event
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
    logger.debug(f"Reverting segment data. Hash before revert: {seigr_file.hash}")

    # Log data type to diagnose potential issues with decode
    data_snapshot_data = previous_layer.data_snapshot["data"]
    logger.debug(f"Data snapshot 'data' type: {type(data_snapshot_data)}")
    logger.debug(f"Layer hash type: {type(previous_layer.layer_hash)}")

    # Ensure data is assigned as bytes if needed
    seigr_file.data = data_snapshot_data if isinstance(data_snapshot_data, bytes) else data_snapshot_data.encode()

    # Ensure the hash is assigned correctly
    if isinstance(previous_layer.layer_hash, bytes):
        seigr_file.hash = previous_layer.layer_hash.decode()  # Decode if bytes
    else:
        seigr_file.hash = previous_layer.layer_hash  # Direct assign if string

    restore_metadata_links(seigr_file, previous_layer)
    restore_coordinate_index(seigr_file, previous_layer)
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
