import time
import hashlib
import uuid
import logging
import json
from os import urandom
import secrets
from datetime import datetime

# Set up centralized logging
logging.basicConfig(
    filename='seigr_hypha_crypt.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 16  # Salt size in bytes
SEIGR_SIZE = 304 * 1024  # Approximate target size for each .seigr file segment (~539 KB)
TRACE_CODE = "53194"  # Unique trace code for Seigr Urcelial-net
MAX_TREE_DEPTH = 6  # Max depth of hash tree layers for cross-referencing

### Senary Encoding and Decoding Functions ###

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string."""
    senary_str = ""
    previous_value = 1
    for i, byte in enumerate(binary_data):
        transformed_byte = _substitution_permutation(byte + previous_value, i)
        previous_value = transformed_byte
        senary_str += _base6_encode(transformed_byte)
    logger.debug("Encoded data to senary format.")
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    binary_data = bytearray()
    previous_value = 1
    for i in range(0, len(senary_str), 2):
        byte = _base6_decode(senary_str[i:i + 2])
        reversed_byte = _reverse_substitution_permutation(byte, previous_value, i // 2)
        binary_data.append(reversed_byte)
        previous_value = byte
    logger.debug("Decoded senary data to binary format.")
    return bytes(binary_data)

# Private helper functions for encoding and decoding

def _substitution_permutation(value: int, position: int) -> int:
    substituted = (value ^ (position * 17 + 23)) & 0xFF
    rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
    return rotated

def _reverse_substitution_permutation(value: int, prev_val: int, position: int) -> int:
    rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
    substituted = (rotated ^ (position * 17 + 23)) & 0xFF
    return (substituted - prev_val) & 0xFF

def _base6_encode(byte: int) -> str:
    """Encodes a single byte to base-6 with 2-character padding."""
    senary = [str((byte // 6**i) % 6) for i in range((byte.bit_length() + 1) // 3 + 1)]
    return ''.join(reversed(senary)).zfill(2)

def _base6_decode(senary_str: str) -> int:
    """Decodes a base-6 encoded string to a single byte."""
    byte = 0
    for char in senary_str:
        byte = byte * 6 + int(char)
    return byte

### Hashing and Salt Generation Functions ###

def generate_hash(data: str, salt: str = None, key: str = None, hash_type="primary") -> str:
    """Generates a hash with optional key and salt, for primary or secondary purposes."""
    salt = salt or dynamic_salt()
    data_to_hash = f"{TRACE_CODE}:{salt}:{data}:{key if key else ''}"
    
    if hash_type == "primary":
        logger.debug(f"Generating primary SHA-256 hash with salt={salt}")
        return hashlib.sha256(data_to_hash.encode()).hexdigest()
    elif hash_type == "secondary":
        logger.debug(f"Generating secondary SHA-512 hash with salt={salt}")
        return hashlib.sha512(data_to_hash.encode()).hexdigest()
    else:
        raise ValueError("Invalid hash_type specified. Use 'primary' or 'secondary'.")

def dynamic_salt(seed: str = None) -> str:
    """Generates a dynamic salt, optionally seeded."""
    unique_id = uuid.uuid4()
    timestamp = int(time.time() * 1e6)
    entropy = int.from_bytes(secrets.token_bytes(2), 'little')
    salt = f"{unique_id.hex}{timestamp:016x}{entropy:04x}"
    if seed:
        salt += seed
    logger.debug(f"Generated dynamic salt: {salt}")
    return salt

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
        self.primary_hash = hashlib.sha256(hash_input).hexdigest()
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
                layer_hash = hashlib.sha512(hash_input).hexdigest()
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
            "timestamp": datetime.utcnow().isoformat(),
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

    def display_hash_tree(self):
        """
        Provides a formatted display of the hash tree structure for debugging or tracing.
        """
        print("=== Hash Tree for Segment ID:", self.segment_id, "===")
        for depth, hashes in self.tree.items():
            print(f"{depth}: {hashes}")
        print("=======================================")
        logger.info(f"Hash tree displayed for segment {self.segment_id}")
