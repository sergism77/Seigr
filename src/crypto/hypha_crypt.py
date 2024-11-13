import logging
from os import urandom
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from src.crypto.hash_utils import hypha_hash
from src.crypto.key_derivation import generate_salt, derive_key
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary
from src.crypto.cbor_utils import encode_data as cbor_encode, decode_data as cbor_decode
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import OperationLog, IntegrityVerification, VerificationStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

# Set up centralized logging
logger = logging.getLogger(__name__)

class HyphaCrypt:
    def __init__(self, data: bytes, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
        """
        Initializes HyphaCrypt for encryption, hashing, and traceability.

        Args:
            data (bytes): The data segment to be encrypted, hashed, and logged.
            segment_id (str): Unique identifier for the segment.
            hash_depth (int): Depth for hierarchical hashing.
            use_senary (bool): Use senary encoding for output.
        """
        self.data = data
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary
        self.primary_hash = None
        self.tree = {}  # Stores hash tree layers
        self.layer_logs = []  # Protocol buffer entries for each hash layer event

    ### Encryption Functions ###

    def generate_encryption_key(self, password: str = None) -> bytes:
        """Generates or derives an encryption key based on an optional password."""
        salt = generate_salt()
        key = derive_key(password, salt) if password else Fernet.generate_key()
        logger.debug(f"Generated encryption key for segment {self.segment_id}")
        return key

    def encrypt_data(self, key: bytes) -> bytes:
        """Encrypts data using a Fernet encryption key."""
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(self.data)
        logger.debug(f"Data encrypted for segment {self.segment_id}")
        return encrypted_data

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypts data using a Fernet encryption key."""
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        logger.debug(f"Data decrypted for segment {self.segment_id}")
        return decrypted_data

    ### Hierarchical Hash Tree and Logging ###

    def compute_primary_hash(self):
        """Computes and logs the primary hash for the data segment."""
        self.primary_hash = hypha_hash(self.data, senary_output=self.use_senary)
        logger.info(f"Primary hash computed for segment {self.segment_id}: {self.primary_hash}")
        return self.primary_hash

    def compute_layered_hashes(self):
        """Generates a hierarchical hash tree up to the specified depth."""
        if not self.primary_hash:
            self.compute_primary_hash()

        current_layer = [self.primary_hash]
        for depth in range(1, self.hash_depth + 1):
            next_layer = []
            for item in current_layer:
                hash_input = f"{item}:{depth}".encode()
                layer_hash = hypha_hash(hash_input, algorithm="sha512", senary_output=self.use_senary)
                next_layer.append(layer_hash)
                self._log_layer_event(depth, layer_hash)

            self.tree[f"Layer_{depth}"] = next_layer
            current_layer = next_layer

        logger.info(f"Layered hashes computed for segment {self.segment_id} up to depth {self.hash_depth}")
        return self.tree

    def _log_layer_event(self, depth, layer_hash):
        """Logs each layer's hash with metadata using a protocol buffer entry."""
        log_entry = OperationLog(
            operation_id=f"layer_{depth}_{self.segment_id}",
            operation_type="layer_hash",
            performed_by=self.segment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            details=f"Layer {depth} - Hash: {layer_hash}"
        )
        self.layer_logs.append(log_entry)
        logger.debug(f"Layer event logged at depth {depth} for segment {self.segment_id}")

    def export_log_tree(self, use_cbor: bool = True):
        """
        Exports the hash tree log in CBOR or binary format for compatibility.

        Args:
            use_cbor (bool): Export as CBOR if True, else protobuf binary.

        Returns:
            str: Path to the saved log file.
        """
        filename = f"{self.segment_id}_tree_log.cbor" if use_cbor else f"{self.segment_id}_tree_log.pb"
        serialized_data = cbor_encode([log_entry.SerializeToString() for log_entry in self.layer_logs]) if use_cbor else b''.join([log_entry.SerializeToString() for log_entry in self.layer_logs])

        with open(filename, 'wb') as f:
            f.write(serialized_data)
        logger.info(f"Tree log exported to {filename} for segment {self.segment_id}")
        return filename

    ### Integrity Verification ###

    def verify_integrity(self, reference_tree, partial_depth=None):
        """
        Verifies the integrity of the segment by comparing the hash tree with a reference.

        Args:
            reference_tree (dict): Reference hash tree for comparison.
            partial_depth (int): Depth of partial verification. Verifies full depth if None.

        Returns:
            dict: Verification results with match status and failed layers if any.
        """
        partial_depth = partial_depth or self.hash_depth
        generated_tree = self.compute_layered_hashes()
        verification_results = {
            "status": "success",
            "failed_layers": []
        }

        for depth in range(1, partial_depth + 1):
            generated_layer = generated_tree.get(f"Layer_{depth}")
            reference_layer = reference_tree.get(f"Layer_{depth}")
            if generated_layer != reference_layer:
                verification_results["status"] = "failed"
                verification_results["failed_layers"].append(depth)
                logger.warning(f"Integrity check failed at depth {depth} for segment {self.segment_id}")

        logger.info(f"Integrity verification for segment {self.segment_id}: {verification_results['status']}")
        return verification_results

    def log_integrity_verification(self, status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None) -> IntegrityVerification:
        """
        Logs the result of an integrity verification using protocol buffer format.

        Args:
            status (str): Verification status ("SUCCESS" or "FAILED").
            verifier_id (str): ID of the verifier.
            integrity_level (str): Integrity verification level.
            details (dict): Additional verification details.

        Returns:
            IntegrityVerification: Generated log entry.
        """
        verification_entry = IntegrityVerification(
            verification_id=f"{self.segment_id}_verification",
            verifier_id=verifier_id,
            status=VerificationStatus.VERIFIED if status.upper() == "SUCCESS" else VerificationStatus.COMPROMISED,
            timestamp=datetime.now(timezone.utc).isoformat(),
            integrity_level=integrity_level,
            verification_notes=details or {}
        )
        logger.info(f"Logged integrity verification for segment {self.segment_id}: {status}")
        return verification_entry
