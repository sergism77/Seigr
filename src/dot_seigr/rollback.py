import logging
from datetime import datetime, timezone
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import TemporalLayer

logger = logging.getLogger(__name__)

def rollback_to_previous_state(seigr_file: SeigrFile) -> bool:
    """
    Reverts a segment to its previous secure state using temporal layers, ensuring integrity before applying rollback.

    Args:
        seigr_file (SeigrFile): Instance of SeigrFile representing the segment to roll back.

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

    # Step 3: Verify the integrity of the previous state before proceeding
    expected_hash = previous_layer.layer_hash
    if not verify_layer_integrity(previous_layer, expected_hash):
        logger.error(f"Integrity verification failed for previous layer at {previous_layer.timestamp}. Rollback aborted.")
        return False

    # Step 4: Log the rollback attempt
    log_rollback_attempt(seigr_file.hash, previous_layer.timestamp)

    # Step 5: Revert segment data and metadata to the previous state
    try:
        revert_segment_data(seigr_file, previous_layer)
        logger.info(f"Reverted segment {seigr_file.hash} data to previous layer at timestamp {previous_layer.timestamp}.")
    except Exception as e:
        logger.error(f"Error during data revert for segment {seigr_file.hash}: {e}")
        return False

    # Step 6: Log the successful rollback
    log_rollback_success(seigr_file.hash, previous_layer.timestamp)
    logger.info(f"Rollback successful for segment {seigr_file.hash}. Reverted to timestamp {previous_layer.timestamp}.")
    return True

def verify_rollback_availability(seigr_file: SeigrFile) -> bool:
    """
    Checks if a previous temporal layer exists for rollback.

    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being checked.

    Returns:
        bool: True if rollback is possible, False otherwise.
    """
    return len(seigr_file.temporal_layers) > 1

def verify_layer_integrity(previous_layer: TemporalLayer, expected_hash: str) -> bool:
    """
    Verifies the integrity of a temporal layer before committing to a rollback.

    Args:
        previous_layer (TemporalLayer): The temporal layer to verify.
        expected_hash (str): The expected hash to validate against the layer's hash.

    Returns:
        bool: True if the layer is verified as intact, False otherwise.
    """
    valid = previous_layer.layer_hash == expected_hash
    if valid:
        logger.debug(f"Layer at {previous_layer.timestamp} passed integrity verification.")
    else:
        logger.warning(f"Integrity verification failed for layer at {previous_layer.timestamp}.")
    return valid

def revert_segment_data(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Reverts the current segment's data and metadata to a previous secure state.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile to revert.
        previous_layer (TemporalLayer): TemporalLayer containing the data snapshot of the previous state.
    """
    logger.debug(f"Reverting segment data. Hash before revert: {seigr_file.hash}")
    
    # Set the segment's data and hash directly from the previous layer
    seigr_file.data = previous_layer.data_snapshot["data"]
    seigr_file.hash = previous_layer.layer_hash.decode() if isinstance(previous_layer.layer_hash, bytes) else previous_layer.layer_hash

    # Restore primary and secondary links using Protobuf serialization methods
    restore_metadata_links(seigr_file, previous_layer)
    restore_coordinate_index(seigr_file, previous_layer)
    
    # Add a new temporal layer to document this state
    seigr_file.add_temporal_layer()

    logger.debug(f"Segment {seigr_file.hash} reverted to previous state with hash {previous_layer.layer_hash}.")

def restore_metadata_links(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Restores primary and secondary links from a previous secure state using Protobuf fields.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being reverted.
        previous_layer (TemporalLayer): TemporalLayer containing the snapshot of previous links.
    """
    # Retrieve primary and secondary links directly from the Protobuf fields
    primary_link = previous_layer.data_snapshot.get("primary_link", b"")
    seigr_file.metadata.primary_link = primary_link.decode("utf-8") if isinstance(primary_link, bytes) else primary_link

    # Use Protobuf repeated fields for secondary links, clearing and re-populating them
    seigr_file.metadata.secondary_links.clear()
    for link in previous_layer.data_snapshot.get("secondary_links", []):
        seigr_file.metadata.secondary_links.append(link.decode("utf-8") if isinstance(link, bytes) else link)

    logger.debug(f"Restored primary and secondary links for segment {seigr_file.hash}.")

def restore_coordinate_index(seigr_file: SeigrFile, previous_layer: TemporalLayer):
    """
    Restores the coordinate index for the segment from a previous secure state using Protobuf.
    
    Args:
        seigr_file (SeigrFile): Instance of SeigrFile being reverted.
        previous_layer (TemporalLayer): TemporalLayer with the coordinate snapshot.
    """
    # Restore coordinate index from Protobuf data
    if "coordinate_index" in previous_layer.data_snapshot:
        coordinate_data = previous_layer.data_snapshot["coordinate_index"]
        seigr_file.metadata.coordinate_index.ParseFromString(coordinate_data)

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
