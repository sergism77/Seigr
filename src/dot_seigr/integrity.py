# src/dot_seigr/integrity.py
import logging
from ..crypto.hypha_crypt import HyphaHasher

logger = logging.getLogger(__name__)
hasher = HyphaHasher()

def verify_integrity(stored_hash: str, senary_data: str) -> bool:
    """Verifies integrity by comparing computed hash with stored hash."""
    computed_hash = hasher.generate_primary_hash(senary_data)
    valid = computed_hash == stored_hash
    logger.info(f"Integrity check {'passed' if valid else 'failed'} for .seigr file.")
    return valid
