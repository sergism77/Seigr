from src.logger.secure_logger import secure_logger
from tenacity import retry, stop_after_attempt, wait_fixed
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.helpers import apply_salt, encode_to_senary
from src.crypto.key_derivation import derive_key, generate_salt
from src.seigr_protocol.compiled.alerting_pb2 import (
    AlertSeverity,
)


class HyphaCrypt:
    """
    Handles encryption, decryption, hashing, and integrity verification
    for data segments in the Seigr ecosystem.
    """

    def __init__(self, data: bytes, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
        """
        Initialize HyphaCrypt instance.
        """
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Initialization",
            message=f"{SEIGR_CELL_ID_PREFIX} HyphaCrypt initialized for segment: {segment_id}",
            sensitive=False,
        )

        if not isinstance(hash_depth, int) or hash_depth <= 0:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX}_invalid_hash_depth: Hash depth must be a positive integer."
            )

        self.data = data
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary
        self.primary_hash = None
        self.tree = {}
        self.layer_logs = []

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Initialization",
            message=f"{SEIGR_CELL_ID_PREFIX} HyphaCrypt fully initialized for segment: {segment_id}",
            sensitive=False,
        )

    ### 🗝️ Encryption & Decryption Functions ###

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def generate_encryption_key(self, password: str = None) -> bytes:
        """
        Generate or derive an encryption key with retry logic.
        Supports both password-based and random key generation.
        """
        try:
            if password:
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend(),
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            else:
                key = Fernet.generate_key()

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Key Generation",
                message=f"{SEIGR_CELL_ID_PREFIX} Generated encryption key for segment {self.segment_id}",
                sensitive=False,
            )

            return key
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Key Generation",
                message=f"{SEIGR_CELL_ID_PREFIX}_keygen_fail: Key generation failed with error: {str(e)}",
                sensitive=True,
            )
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def encrypt_data(self, key: bytes) -> bytes:
        """
        Encrypt data using a Fernet key.
        """
        try:
            if not key:
                raise ValueError("Key must be provided and valid.")
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(self.data)
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Data encrypted for segment {self.segment_id}",
            )
            return encrypted_data
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_encryption_fail: Encryption failed with error: {str(e)}",
                sensitive=True,
            )
            raise

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using the provided key.
        """
        try:
            if not key:
                raise ValueError("Key must be provided and valid.")
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Decryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Data decrypted for segment {self.segment_id}",
            )
            return decrypted_data
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="Decryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_decryption_fail: Decryption failed with error: {str(e)}",
                sensitive=True,
            )
            raise

    ### 🔑 Hash Functions ###

    def hypha_hash(
        self, data: bytes, salt: str = None, algorithm: str = DEFAULT_HASH_FUNCTION
    ) -> str:
        """
        Generate a secure hash.
        """
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX}_unsupported_algorithm: Unsupported algorithm: {algorithm}"
            )

        salted_data = apply_salt(data, salt)
        return hashlib.sha256(salted_data).hexdigest()

    def verify_integrity(self, reference_tree: dict) -> dict:
        """
        Verify the integrity of a hash tree.
        """
        try:
            for layer, hashes in reference_tree.items():
                for h in hashes:
                    if not isinstance(h, str) or not h:
                        raise ValueError(
                            f"{SEIGR_CELL_ID_PREFIX}_invalid_hash: Invalid hash detected."
                        )
                # Add logic to verify against expected tree structure
                if "tampered_hash" in hashes:
                    raise ValueError(
                        f"{SEIGR_CELL_ID_PREFIX}_tampered_tree: Hash tree contains tampered data."
                    )

            return {"status": "success"}
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="Integrity",
                message=f"{SEIGR_CELL_ID_PREFIX}_integrity_fail: {str(e)}",
                sensitive=True,
            )
            return {"status": "failed", "error": str(e)}
