# src/crypto/hypha_crypt.py
import logging
import json
from os import urandom
from datetime import datetime, timezone
import secrets
import uuid
from cryptography.fernet import Fernet

# Import encoding utilities and hashing functions
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_constants import (
    SALT_SIZE, SEIGR_SIZE, TRACE_CODE, MAX_TREE_DEPTH,
    DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
)

# Set up centralized logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='seigr_hypha_crypt.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

### Encryption Functions ###

def generate_encryption_key() -> bytes:
    """
    Generates a new encryption key for symmetric encryption.
    
    Returns:
        bytes: A key for use with Fernet encryption.
    """
    return Fernet.generate_key()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using the provided encryption key.
    
    Args:
        data (bytes): Data to be encrypted.
        key (bytes): Encryption key.
    
    Returns:
        bytes: Encrypted data.
    """
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    logger.debug("Data encrypted successfully.")
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data using the provided encryption key.
    
    Args:
        encrypted_data (bytes): Encrypted data to decrypt.
        key (bytes): Encryption key.
    
    Returns:
        bytes: Decrypted data.
    """
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    logger.debug("Data decrypted successfully.")
    return decrypted_data

### Pseudo-Random Number Generation ###

def secure_random(seed: int = None) -> int:
    """Generates a secure random number using the xorshift algorithm."""
    if seed is None:
        seed = int.from_bytes(urandom(4), 'little')
    x = seed
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5) & 0xFFFFFFFF
    logger.debug(f"Generated secure random number: {x}")
    return x & 0xFFFFFFFF

### Hierarchical Hash Tree and Logging ###

class HyphaCrypt:
    def __init__(self, data: bytes, segment_id: str):
        """
        Initializes HyphaCrypt for handling encryption, hashing, and traceability.
        
        Args:
            data (bytes): The data segment to be encoded and hashed.
            segment_id (str): Unique identifier for the segment (UUID or derived hash).
        """
        self.data = data
        self.segment_id = segment_id
        self.primary_hash = None
        self.tree = {}  # Structure to store hash tree layers
        self.layer_logs = []  # Memory structure to retain all hash logs for traceability

    def compute_primary_hash(self):
        """
        Computes and stores the primary SHA-256 hash of the data segment, including TRACE_CODE.
        """
        hash_input = TRACE_CODE.encode() + self.data
        self.primary_hash = hypha_hash(hash_input)  # Use hypha_hash from hash_utils for consistency
        logger.info(f"Primary hash computed: {self.primary_hash} for segment {self.segment_id}")
        return self.primary_hash

    def compute_layered_hashes(self, layers=MAX_TREE_DEPTH):
        """
        Computes a tree of hashes up to a specified depth, creating interconnected layers.
        
        Args:
            layers (int): Depth of the hashing tree.
        """
        if not self.primary_hash:
            self.compute_primary_hash()
        
        current_layer = [self.primary_hash]
        for depth in range(1, layers + 1):
            next_layer = []
            for item in current_layer:
                hash_input = f"{TRACE_CODE}:{item}:{depth}".encode()
                layer_hash = hypha_hash(hash_input, algorithm="sha512")
                next_layer.append(layer_hash)
                self._log_layer_event(depth, layer_hash)
            
            self.tree[f"Layer_{depth}"] = next_layer
            current_layer = next_layer

        logger.info(f"Layered hashes computed up to depth {layers} for segment {self.segment_id}")
        return self.tree

    def _log_layer_event(self, depth, layer_hash):
        """
        Logs each layer's hash with metadata to `layer_logs`.
        
        Args:
            depth (int): The depth of the layer in the hash tree.
            layer_hash (str): The computed hash of the current layer.
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "segment_id": self.segment_id,
            "depth": depth,
            "layer_hash": layer_hash
        }
        self.layer_logs.append(log_entry)
        logger.debug(f"Logged Layer {depth} - Hash: {layer_hash} for Segment {self.segment_id}")

    def export_log_tree(self):
        """
        Exports the hash tree log to JSON for potential visualization and tracing.
        
        Returns:
            str: Path to the saved JSON file containing layer logs.
        """
        filename = f"{self.segment_id}_tree_log.json"

        with open(filename, 'w') as f:
            json.dump(self.layer_logs, f, indent=4)
        
        logger.info(f"Tree log exported to {filename} for segment {self.segment_id}")
        return filename

    def verify_integrity(self, reference_tree):
        """
        Verifies the integrity of the segment by comparing its hash tree with a reference tree.
        
        Args:
            reference_tree (dict): The hash tree structure to verify against.
        
        Returns:
            bool: True if the hash trees match, False otherwise.
        """
        current_tree = self.compute_layered_hashes()
        if current_tree == reference_tree:
            logger.info(f"Integrity verified for segment {self.segment_id}")
            return True
        else:
            logger.warning(f"Integrity check failed for segment {self.segment_id}")
            return False
