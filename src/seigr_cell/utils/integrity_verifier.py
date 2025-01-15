import hashlib
from typing import Dict, Any
from src.logger.secure_logger import secure_logger  # Secure logger for audit logging


def verify_integrity(data: bytes, primary_hash: str) -> bool:
    """
    Verifies the primary integrity hash of the given data.

    Args:
        data (bytes): Data to verify.
        primary_hash (str): Expected primary hash.

    Returns:
        bool: True if the data's hash matches the primary hash, False otherwise.
    """
    try:
        calculated_hash = hashlib.sha256(data).hexdigest()
        is_valid = calculated_hash == primary_hash

        secure_logger.log_audit_event(
            severity=1 if is_valid else 3,
            category="Integrity Verification",
            message=f"Primary integrity verification {'succeeded' if is_valid else 'failed'}.",
            sensitive=False,
        )
        return is_valid
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Integrity Verification",
            message=f"Error during primary integrity verification: {e}",
            sensitive=True,
        )
        raise ValueError("Primary integrity verification failed.") from e


def verify_hierarchical_integrity(data: bytes, hash_tree: Dict[str, Any]) -> bool:
    """
    Verifies the hierarchical hash structure for the given data.

    Args:
        data (bytes): Data to verify.
        hash_tree (dict): Reference hash tree containing chunk hashes and root hash.

    Returns:
        bool: True if the hierarchical hash structure is valid, False otherwise.
    """
    if not isinstance(hash_tree, dict):
        raise TypeError("Hash tree must be a dictionary.")

    try:
        # Extract chunk size and reference root hash
        chunk_size = hash_tree.get("chunk_size", 1024)  # Default to 1024 bytes if not specified
        reference_root = hash_tree.get("root_hash")
        reference_chunks = hash_tree.get("chunk_hashes", [])

        # Verify individual chunks
        data_length = len(data)
        calculated_chunks = []

        for i in range(0, data_length, chunk_size):
            chunk = data[i : i + chunk_size]
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            calculated_chunks.append(chunk_hash)

        if calculated_chunks != reference_chunks:
            secure_logger.log_audit_event(
                severity=3,
                category="Hierarchical Integrity Verification",
                message="Chunk-level integrity verification failed.",
                sensitive=False,
            )
            return False

        # Reduce the hash tree to a single root hash
        while len(calculated_chunks) > 1:
            next_level = []
            for j in range(0, len(calculated_chunks), 2):
                left = calculated_chunks[j]
                right = calculated_chunks[j + 1] if j + 1 < len(calculated_chunks) else left
                combined_hash = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined_hash)
            calculated_chunks = next_level

        # Validate the final root hash
        root_hash = calculated_chunks[0]
        is_valid = root_hash == reference_root

        secure_logger.log_audit_event(
            severity=1 if is_valid else 3,
            category="Hierarchical Integrity Verification",
            message=f"Hierarchical integrity verification {'succeeded' if is_valid else 'failed'}.",
            sensitive=False,
        )
        return is_valid
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Hierarchical Integrity Verification",
            message=f"Error during hierarchical integrity verification: {e}",
            sensitive=True,
        )
        raise ValueError("Hierarchical integrity verification failed.") from e


def generate_hash_tree(data: bytes, chunk_size: int = 1024) -> Dict[str, Any]:
    """
    Generates a hierarchical hash tree for the given data.

    Args:
        data (bytes): Data for which the hash tree is generated.
        chunk_size (int): Size of chunks in bytes for hashing. Default is 1024 bytes.

    Returns:
        dict: A dictionary containing the chunk hashes and the root hash.
    """
    try:
        data_length = len(data)
        chunks = []

        # Calculate hash for each chunk
        for i in range(0, data_length, chunk_size):
            chunk = data[i : i + chunk_size]
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            chunks.append(chunk_hash)

        calculated_chunks = chunks[:]

        # Calculate root hash
        while len(calculated_chunks) > 1:
            next_level = []
            for j in range(0, len(calculated_chunks), 2):
                left = calculated_chunks[j]
                right = calculated_chunks[j + 1] if j + 1 < len(calculated_chunks) else left
                combined_hash = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined_hash)
            calculated_chunks = next_level

        root_hash = calculated_chunks[0]

        secure_logger.log_audit_event(
            severity=1,
            category="Hash Tree Generation",
            message="Hash tree generated successfully.",
            sensitive=False,
        )

        return {
            "chunk_size": chunk_size,
            "chunk_hashes": chunks,
            "root_hash": root_hash,
        }
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Hash Tree Generation",
            message=f"Error during hash tree generation: {e}",
            sensitive=True,
        )
        raise ValueError("Failed to generate hash tree.") from e
