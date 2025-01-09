import hashlib


def verify_integrity(data: bytes, primary_hash: str) -> bool:
    """
    Verifies the primary integrity hash of the given data.

    Args:
        data (bytes): Data to verify.
        primary_hash (str): Expected primary hash.

    Returns:
        bool: True if the data's hash matches the primary hash, False otherwise.
    """
    calculated_hash = hashlib.sha256(data).hexdigest()
    return calculated_hash == primary_hash


def verify_hierarchical_integrity(data: bytes, hash_tree: dict) -> bool:
    """
    Verifies the hierarchical hash structure for the given data.

    Args:
        data (bytes): Data to verify.
        hash_tree (dict): Reference hash tree.

    Returns:
        bool: True if the hierarchical hash structure is valid, False otherwise.
    """
    if not isinstance(hash_tree, dict):
        raise TypeError("Hash tree must be a dictionary.")
        
    try:
        # Compute the hashes in a hierarchical structure
        data_length = len(data)
        chunk_size = hash_tree.get("chunk_size", 1024)  # Default chunk size is 1024 bytes
        calculated_tree = []

        # Hash each chunk and store in the calculated tree
        for i in range(0, data_length, chunk_size):
            chunk = data[i:i + chunk_size]
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            calculated_tree.append(chunk_hash)

        # Reduce the hash tree to a single root hash
        while len(calculated_tree) > 1:
            next_level = []
            for j in range(0, len(calculated_tree), 2):
                left = calculated_tree[j]
                right = calculated_tree[j + 1] if j + 1 < len(calculated_tree) else left
                combined_hash = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined_hash)
            calculated_tree = next_level

        # Final root hash should match the primary hash in the reference tree
        root_hash = calculated_tree[0]
        reference_root = hash_tree.get("root_hash")
        return root_hash == reference_root

    except Exception as e:
        raise ValueError(f"Error during hierarchical integrity verification: {e}")
