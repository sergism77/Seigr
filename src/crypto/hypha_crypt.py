# src/crypto/hypha_crypt.py

import logging
from os import urandom
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from src.crypto.hash_utils import hypha_hash
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary
from src.crypto.cbor_utils import cbor_encode, cbor_decode
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import OperationLog, IntegrityVerification

# Set up centralized logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='seigr_hypha_crypt.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

### Encryption Functions ###

def generate_encryption_key(password: str = None) -> bytes:
    """Generates a symmetric encryption key, optionally derived from a password."""
    if password:
        return hypha_hash(password)[:32]
    return Fernet.generate_key()

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password and a salt."""
    return hypha_hash(password + salt.hex())[:32]

def generate_salt() -> bytes:
    """Generates a cryptographic salt."""
    return urandom(16)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using the provided encryption key."""
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts data using the provided encryption key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

### Hierarchical Hash Tree and Logging ###

class HyphaCrypt:
    def __init__(self, data: bytes, segment_id: str, use_senary: bool = True):
        """
        Initializes HyphaCrypt for encryption, hashing, and traceability.

        Args:
            data (bytes): The data segment to be encoded and hashed.
            segment_id (str): Unique identifier for the segment (UUID or derived hash).
            use_senary (bool): Determines if senary encoding is applied to hash outputs.
        """
        self.data = data
        self.segment_id = segment_id
        self.primary_hash = None
        self.tree = {}  # Stores hash tree layers
        self.layer_logs = []  # Keeps all hash logs for traceability
        self.use_senary = use_senary

    def compute_primary_hash(self):
        """Computes and stores the primary hash of the data segment."""
        self.primary_hash = hypha_hash(self.data, senary_output=self.use_senary)
        logger.info(f"Primary hash computed: {self.primary_hash} for segment {self.segment_id}")
        return self.primary_hash

    def compute_layered_hashes(self, layers=4):
        """Computes a hierarchical tree of hashes up to a specified depth."""
        if not self.primary_hash:
            self.compute_primary_hash()

        current_layer = [self.primary_hash]
        for depth in range(1, layers + 1):
            next_layer = []
            for item in current_layer:
                hash_input = f"{item}:{depth}".encode()
                layer_hash = hypha_hash(hash_input, algorithm="sha512", senary_output=self.use_senary)
                next_layer.append(layer_hash)
                self._log_layer_event(depth, layer_hash)

            self.tree[f"Layer_{depth}"] = next_layer
            current_layer = next_layer

        logger.info(f"Layered hashes computed up to depth {layers} for segment {self.segment_id}")
        return self.tree

    def _log_layer_event(self, depth, layer_hash):
        """Logs each layer's hash with metadata as OperationLog to the log list."""
        log_entry = OperationLog(
            operation_type="layer_hash",
            performed_by=self.segment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            details=f"Layer {depth} - Hash: {layer_hash}"
        )
        self.layer_logs.append(log_entry)
        logger.debug(f"Logged Layer {depth} - Hash: {layer_hash} for Segment {self.segment_id}")

    def export_log_tree(self, use_cbor: bool = True):
        """
        Exports the hash tree log to CBOR for efficient visualization and tracing.

        Args:
            use_cbor (bool): Exports as CBOR if True, otherwise uses protobuf binary format.

        Returns:
            str: Path to the saved log file.
        """
        filename = f"{self.segment_id}_tree_log.cbor" if use_cbor else f"{self.segment_id}_tree_log.pb"
        serialized_data = cbor_encode([log_entry.SerializeToString() for log_entry in self.layer_logs]) if use_cbor else b''.join([log_entry.SerializeToString() for log_entry in self.layer_logs])

        with open(filename, 'wb') as f:
            f.write(serialized_data)
        logger.info(f"Tree log exported to {filename} for segment {self.segment_id}")
        return filename

    def verify_integrity(self, reference_tree, partial_depth=None):
        """
        Verifies the integrity of the segment by comparing its hash tree with a reference tree.

        Args:
            reference_tree (dict): The hash tree structure to verify against.
            partial_depth (int): Depth of partial verification. Verifies full depth if None.

        Returns:
            bool: True if the hash trees match up to the specified depth, otherwise False.
        """
        current_tree = self.compute_layered_hashes(layers=partial_depth or 4)
        for depth in range(1, (partial_depth or 4) + 1):
            current_layer = current_tree.get(f"Layer_{depth}")
            reference_layer = reference_tree.get(f"Layer_{depth}")
            if current_layer != reference_layer:
                logger.warning(f"Integrity check failed at depth {depth} for segment {self.segment_id}")
                return False
        logger.info(f"Integrity verified up to depth {partial_depth or 4} for segment {self.segment_id}")
        return True

    def log_integrity_verification(self, status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None) -> IntegrityVerification:
        """
        Logs the result of an integrity verification process.

        Args:
            status (str): Verification status (e.g., "SUCCESS", "FAILED").
            verifier_id (str): ID of the verifier.
            integrity_level (str): Level of integrity verification.
            details (dict, optional): Additional details about the verification.

        Returns:
            IntegrityVerification: The generated log entry.
        """
        verification_entry = IntegrityVerification(
            status=status,
            timestamp=datetime.now(timezone.utc).isoformat(),
            verifier_id=verifier_id,
            integrity_level=integrity_level,
            details=details or {}
        )
        logger.info(f"Logged integrity verification: {verification_entry}")
        return verification_entry
