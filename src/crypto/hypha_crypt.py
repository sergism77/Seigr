import logging

from cryptography.fernet import Fernet

from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.helpers import apply_salt, encode_to_senary
from src.crypto.key_derivation import derive_key, generate_salt
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)

# Centralized logging setup
logger = logging.getLogger(__name__)


class HyphaCrypt:
    """
    Handles encryption, decryption, hashing, and integrity verification
    for data segments in the Seigr ecosystem.
    """

    def __init__(self, data: bytes, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
        """
        Initialize HyphaCrypt instance.

        Args:
            data (bytes): Data segment to process.
            segment_id (str): Unique identifier for the segment.
            hash_depth (int): Number of hash layers.
            use_senary (bool): Whether to encode hash outputs in senary format.
        """
        self.data = data
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary
        self.primary_hash = None
        self.tree = {}  # Hash tree layers
        self.layer_logs = []  # Operation logs for each hash layer

        logger.info(f"{SEIGR_CELL_ID_PREFIX} HyphaCrypt initialized for segment: {segment_id}")

    ### 🗝️ Encryption & Decryption Functions ###

    def generate_encryption_key(self, password: str = None) -> bytes:
        """
        Generate or derive an encryption key.

        Args:
            password (str, optional): Password for key derivation.

        Returns:
            bytes: Encryption key.
        """
        try:
            salt = generate_salt()
            key = derive_key(password, salt) if password else Fernet.generate_key()
            logger.debug(
                f"{SEIGR_CELL_ID_PREFIX} Generated encryption key for segment {self.segment_id}"
            )
            return key
        except Exception as e:
            self._log_error(f"{SEIGR_CELL_ID_PREFIX}_keygen_fail", "Key generation failed", e)
            raise

    def encrypt_data(self, key: bytes) -> bytes:
        """
        Encrypt data using a Fernet key.

        Args:
            key (bytes): Encryption key.

        Returns:
            bytes: Encrypted data.
        """
        try:
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(self.data)
            logger.debug(f"{SEIGR_CELL_ID_PREFIX} Data encrypted for segment {self.segment_id}")
            return encrypted_data
        except Exception as e:
            self._log_error(f"{SEIGR_CELL_ID_PREFIX}_encryption_fail", "Data encryption failed", e)
            raise

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using a Fernet key.

        Args:
            encrypted_data (bytes): Encrypted data.
            key (bytes): Decryption key.

        Returns:
            bytes: Decrypted data.
        """
        try:
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            logger.debug(f"{SEIGR_CELL_ID_PREFIX} Data decrypted for segment {self.segment_id}")
            return decrypted_data
        except Exception as e:
            self._log_error(f"{SEIGR_CELL_ID_PREFIX}_decryption_fail", "Data decryption failed", e)
            raise

    ### 🔗 Hashing Functions ###

    @staticmethod
    def hypha_hash(
        data: bytes,
        salt: str = None,
        algorithm: str = DEFAULT_HASH_FUNCTION,
        version: int = 1,
        senary_output: bool = False,
    ) -> str:
        """
        Generate a secure hash.

        Args:
            data (bytes): Data to hash.
            salt (str, optional): Salt for hashing.
            algorithm (str): Hash algorithm.
            version (int): Hash version.
            senary_output (bool): Whether to use senary encoding.

        Returns:
            str: Hash result.
        """
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX}_unsupported_algorithm: "
                f"Unsupported hashing algorithm: {algorithm}"
            )

        salted_data = apply_salt(data, salt)
        hash_result = SUPPORTED_HASH_ALGORITHMS[algorithm](salted_data)
        formatted_output = encode_to_senary(hash_result) if senary_output else hash_result.hex()
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated hash using {algorithm}.")
        return f"{SEIGR_VERSION}:{version}:{algorithm}:{formatted_output}"

    ### 🛡️ Integrity Verification ###

    def verify_integrity(self, reference_tree, partial_depth=None):
        """
        Verify the integrity of a data segment.

        Args:
            reference_tree (dict): Reference hash tree.
            partial_depth (int, optional): Depth for partial verification.

        Returns:
            dict: Verification results.
        """
        partial_depth = partial_depth or self.hash_depth
        generated_tree = self.compute_layered_hashes()
        verification_results = {"status": "success", "failed_layers": []}

        for depth in range(1, partial_depth + 1):
            if generated_tree.get(f"Layer_{depth}") != reference_tree.get(f"Layer_{depth}"):
                verification_results["status"] = "failed"
                verification_results["failed_layers"].append(depth)
                logger.warning(f"{SEIGR_CELL_ID_PREFIX} Integrity failed at depth {depth}")

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Integrity verification for segment {self.segment_id}: "
            f"{verification_results['status']}"
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
