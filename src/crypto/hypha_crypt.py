import logging
from os import urandom
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from src.crypto.helpers import apply_salt, encode_to_senary
from src.crypto.key_derivation import generate_salt, derive_key
from src.crypto.cbor_utils import encode_data as cbor_encode, decode_data as cbor_decode
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    OperationLog,
    IntegrityVerification,
    VerificationStatus,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SUPPORTED_HASH_ALGORITHMS,
    SALT_SIZE,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
)

# Set up centralized logging
logger = logging.getLogger(__name__)


class HyphaCrypt:
    def __init__(
        self, data: bytes, segment_id: str, hash_depth: int = 4, use_senary: bool = True
    ):
        self.data = data
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary
        self.primary_hash = None
        self.tree = {}  # Stores hash tree layers
        self.layer_logs = []  # Protocol buffer entries for each hash layer event
        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} HyphaCrypt initialized for segment: {segment_id}"
        )

    ### Encryption Functions ###

    def generate_encryption_key(self, password: str = None) -> bytes:
        """Generates or derives an encryption key based on an optional password."""
        try:
            salt = generate_salt()
            key = derive_key(password, salt) if password else Fernet.generate_key()
            logger.debug(
                f"{SEIGR_CELL_ID_PREFIX} Generated encryption key for segment {self.segment_id}"
            )
            return key
        except Exception as e:
            self._log_error(
                f"{SEIGR_CELL_ID_PREFIX}_keygen_fail", "Key generation failed", e
            )
            raise

    def encrypt_data(self, key: bytes) -> bytes:
        """Encrypts data using a Fernet encryption key."""
        try:
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(self.data)
            logger.debug(
                f"{SEIGR_CELL_ID_PREFIX} Data encrypted for segment {self.segment_id}"
            )
            return encrypted_data
        except Exception as e:
            self._log_error(
                f"{SEIGR_CELL_ID_PREFIX}_encryption_fail", "Data encryption failed", e
            )
            raise

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypts data using a Fernet encryption key."""
        try:
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            logger.debug(
                f"{SEIGR_CELL_ID_PREFIX} Data decrypted for segment {self.segment_id}"
            )
            return decrypted_data
        except Exception as e:
            self._log_error(
                f"{SEIGR_CELL_ID_PREFIX}_decryption_fail", "Data decryption failed", e
            )
            raise

    @staticmethod
    def hypha_hash(
        data: bytes,
        salt: str = None,
        algorithm: str = DEFAULT_HASH_FUNCTION,
        version: int = 1,
        senary_output: bool = False,
    ) -> str:
        """Generates a secure hash of the provided data using the specified algorithm with optional salting."""
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX}_unsupported_algorithm: Unsupported hashing algorithm: {algorithm}"
            )

        salted_data = apply_salt(data, salt)
        hash_result = SUPPORTED_HASH_ALGORITHMS[algorithm](salted_data)
        formatted_output = (
            encode_to_senary(hash_result) if senary_output else hash_result.hex()
        )
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated hash using {algorithm}.")
        return f"{SEIGR_VERSION}:{version}:{algorithm}:{formatted_output}"

    ### Hierarchical Hash Tree and Logging ###

    def compute_primary_hash(self):
        """Computes and logs the primary hash for the data segment."""
        try:
            self.primary_hash = self.hypha_hash(
                self.data, senary_output=self.use_senary
            )
            logger.info(
                f"{SEIGR_CELL_ID_PREFIX} Primary hash computed for segment {self.segment_id}: {self.primary_hash}"
            )
            return self.primary_hash
        except Exception as e:
            self._log_error(
                f"{SEIGR_CELL_ID_PREFIX}_primary_hash_fail",
                "Failed to compute primary hash",
                e,
            )
            raise

    def compute_layered_hashes(self):
        """Generates a hierarchical hash tree up to the specified depth."""
        if not self.primary_hash:
            self.compute_primary_hash()

        current_layer = [self.primary_hash]
        for depth in range(1, self.hash_depth + 1):
            next_layer = []
            for item in current_layer:
                hash_input = f"{item}:{depth}".encode()
                try:
                    layer_hash = self.hypha_hash(
                        hash_input, algorithm="sha512", senary_output=self.use_senary
                    )
                    next_layer.append(layer_hash)
                    self._log_layer_event(depth, layer_hash)
                except Exception as e:
                    self._log_error(
                        f"{SEIGR_CELL_ID_PREFIX}_layer_hash_fail",
                        f"Failed to compute layer {depth} hash",
                        e,
                    )
                    raise
            self.tree[f"Layer_{depth}"] = next_layer
            current_layer = next_layer

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Layered hashes computed for segment {self.segment_id} up to depth {self.hash_depth}"
        )
        return self.tree

    def _log_layer_event(self, depth, layer_hash):
        """Logs each layer's hash with metadata using a protocol buffer entry."""
        log_entry = OperationLog(
            operation_id=f"layer_{depth}_{self.segment_id}",
            operation_type="layer_hash",
            performed_by=self.segment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            details=f"Layer {depth} - Hash: {layer_hash}",
        )
        self.layer_logs.append(log_entry)
        logger.debug(
            f"{SEIGR_CELL_ID_PREFIX} Layer event logged at depth {depth} for segment {self.segment_id}"
        )

    ### Integrity Verification ###

    def verify_integrity(self, reference_tree, partial_depth=None):
        partial_depth = partial_depth or self.hash_depth
        generated_tree = self.compute_layered_hashes()
        verification_results = {"status": "success", "failed_layers": []}

        for depth in range(1, partial_depth + 1):
            generated_layer = generated_tree.get(f"Layer_{depth}")
            reference_layer = reference_tree.get(f"Layer_{depth}")
            if generated_layer != reference_layer:
                verification_results["status"] = "failed"
                verification_results["failed_layers"].append(depth)
                logger.warning(
                    f"{SEIGR_CELL_ID_PREFIX} Integrity check failed at depth {depth} for segment {self.segment_id}"
                )

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Integrity verification for segment {self.segment_id}: {verification_results['status']}"
        )
        return verification_results

    def _log_error(self, error_id, message, exception):
        error_log = ErrorLogEntry(
            error_id=error_id,
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="HyphaCrypt",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{message}: {exception}")
