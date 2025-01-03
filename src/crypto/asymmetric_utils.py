import logging
import uuid
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair, SignatureLog
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity
from src.crypto.constants import (
    SEIGR_CELL_ID_PREFIX,
    DEFAULT_HASH_FUNCTION,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.key_management import generate_rsa_key_pair
from src.crypto.secure_logging import log_secure_action

logger = logging.getLogger(__name__)


### 🛡️ Alert Trigger for High-Severity Events ###

def _trigger_alert(
    message: str, severity: AlertSeverity, recipient_id: str = None
) -> None:
    """
    Trigger an alert for high-severity events.

    Args:
        message (str): Description of the alert.
        severity (AlertSeverity): Severity level of the alert.
        recipient_id (str, optional): ID of the affected recipient.

    Returns:
        None
    """
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        message=message,
        type=AlertType.ALERT_TYPE_SECURITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="crypto_module",
        affected_entity_id=recipient_id,
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {severity}")


### 🗝️ Key Generation with Enhanced Error Reporting ###

def generate_key_pair(
    key_size: int = 2048, retry_attempts: int = 3, retry_delay: int = 2
) -> AsymmetricKeyPair:
    """
    Generate an RSA key pair with retry logic and structured error handling.

    Args:
        key_size (int): Size of the RSA key (default: 2048).
        retry_attempts (int): Number of retries for key generation.
        retry_delay (int): Delay between retries in seconds.

    Returns:
        AsymmetricKeyPair: Protobuf object containing the key pair.

    Raises:
        ValueError: If key generation fails after retries.
    """
    for attempt in range(retry_attempts):
        try:
            private_key, public_key = generate_rsa_key_pair(key_size)
            key_pair_id = f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}"
            key_pair = AsymmetricKeyPair(
                key_pair_id=key_pair_id,
                public_key=serialize_public_key(public_key),
                private_key=serialize_private_key(private_key),
                algorithm=f"RSA-{key_size}",
                creation_timestamp=datetime.now(timezone.utc).isoformat(),
                lifecycle_status="active",
                metadata={
                    "usage": "general",
                    "seigr_protocol": "enabled",
                    "rotation_policy": "annual",
                    "expected_duration": "1 year",
                },
            )
            log_secure_action(
                "Key pair generated",
                {"key_size": key_size, "key_pair_id": key_pair.key_pair_id},
            )
            return key_pair
        except Exception as e:
            logger.warning(f"Key generation attempt {attempt + 1} failed: {str(e)}")
            if attempt == retry_attempts - 1:
                _trigger_alert(
                    f"Key generation failed after {retry_attempts} retries",
                    AlertSeverity.ALERT_SEVERITY_CRITICAL,
                )
                raise ValueError("Failed to generate RSA key pair after retries") from e
            time.sleep(retry_delay * (2**attempt))


### 🔑 Key Serialization ###

def serialize_public_key(public_key) -> bytes:
    """
    Serialize an RSA public key to PEM format.

    Args:
        public_key (rsa.RSAPublicKey): RSA public key object.

    Returns:
        bytes: PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(private_key, encryption_password: bytes = None) -> bytes:
    """
    Serialize an RSA private key to PEM format.

    Args:
        private_key (rsa.RSAPrivateKey): RSA private key object.
        encryption_password (bytes, optional): Password for encryption.

    Returns:
        bytes: PEM-encoded private key.
    """
    encryption_algo = (
        serialization.BestAvailableEncryption(encryption_password)
        if encryption_password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo,
    )


### 🔄 Key Loading with Retry Logic ###

def load_private_key(pem_data: bytes, password: bytes = None, retry_attempts: int = 2):
    """
    Load an RSA private key from PEM data with retry logic.

    Args:
        pem_data (bytes): PEM-encoded private key.
        password (bytes, optional): Password for the private key.
        retry_attempts (int): Number of retry attempts.

    Returns:
        rsa.RSAPrivateKey: Loaded RSA private key object.

    Raises:
        ValueError: If the private key fails to load after retries.
    """
    for attempt in range(retry_attempts):
        try:
            private_key = serialization.load_pem_private_key(pem_data, password=password)
            log_secure_action("Private key loaded", {"protocol": "Seigr"})
            return private_key
        except Exception as e:
            logger.warning(
                f"Attempt {attempt + 1} to load private key failed: {str(e)}"
            )
            if attempt == retry_attempts - 1:
                _trigger_alert(
                    "Private key load failed", AlertSeverity.ALERT_SEVERITY_WARNING
                )
                raise ValueError("Failed to load RSA private key") from e
            time.sleep(2**attempt)


### ✍️ Digital Signature Using Seigr Hashing ###

def sign_data(data: bytes, private_key_pem: bytes, use_senary: bool = True) -> SignatureLog:
    """
    Sign data with a private RSA key using hypha_hash.

    Args:
        data (bytes): Data to sign.
        private_key_pem (bytes): PEM-encoded private key.
        use_senary (bool): Whether to encode the hash in senary format.

    Returns:
        SignatureLog: Protobuf log containing signature metadata.
    """
    private_key = load_private_key(private_key_pem)
    signed_hash = HyphaCrypt.hypha_hash(data, algorithm=DEFAULT_HASH_FUNCTION)
    signature = private_key.sign(
        signed_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return SignatureLog(
        log_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        signature=signature,
        signing_algorithm=DEFAULT_HASH_FUNCTION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
