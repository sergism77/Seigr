"""
Asymmetric Utilities Module

Provides functionality for asymmetric encryption, key pair generation,
and digital signatures in accordance with Seigr protocols.
"""

import logging
import time
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# Local imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.key_management import generate_rsa_key_pair
from src.crypto.secure_logging import log_secure_action
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair

logger = logging.getLogger(__name__)


# 🛡️ Alert Trigger for High-Severity Events
def _trigger_alert(message: str, severity: AlertSeverity, recipient_id: str = None) -> None:
    """
    Trigger an alert for high-severity events.

    Args:
        message (str): Description of the alert.
        severity (AlertSeverity): Severity level of the alert.
        recipient_id (str, optional): ID of the affected recipient.
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
    logger.warning(
        "%s Alert triggered: %s with severity %s",
        SEIGR_CELL_ID_PREFIX,
        alert.message,
        severity.name if hasattr(severity, 'name') else str(severity),
    )



# 🗝️ Key Generation with Retry Logic and Structured Logging
def generate_key_pair(key_size: int = 2048, retry_attempts: int = 3, retry_delay: int = 2) -> AsymmetricKeyPair:
    """
    Generate an RSA key pair with retry logic and structured error handling.
    """
    print("DEBUG: Entered generate_key_pair function.")  # Debug Print
    last_exception = None

    for attempt in range(retry_attempts):
        print(f"DEBUG: Attempt {attempt + 1} to generate RSA key pair.")  # Debug Print
        try:
            private_key, public_key = generate_rsa_key_pair(key_size)
            key_pair_id = f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}"

            log_secure_action(
                "Key pair generated successfully",
                {"key_size": key_size, "key_pair_id": key_pair_id}
            )

            print("DEBUG: Key pair successfully generated.")  # Debug Print

            return AsymmetricKeyPair(
                key_pair_id=key_pair_id,
                public_key=serialize_public_key(public_key),
                private_key=serialize_private_key(private_key),
                algorithm=f"RSA-{key_size}",
                creation_timestamp=datetime.now(timezone.utc).isoformat(),
                lifecycle_status="active",
                metadata={"usage": "general", "rotation_policy": "annual"},
            )
        except Exception as e:
            last_exception = e
            print(f"DEBUG: Attempt {attempt + 1} failed with exception: {str(e)}")  # Debug Print
            logger.warning(
                "%s Key generation attempt %d failed: %s",
                SEIGR_CELL_ID_PREFIX,
                attempt + 1,
                str(e),
            )
            
            if attempt < retry_attempts - 1:
                time.sleep(retry_delay * (2**attempt))  # Only sleep if it's not the last attempt
    
    print("DEBUG: All retry attempts exhausted. Raising ValueError.")  # Debug Print
    logger.error("All attempts to generate key pair have failed. Raising ValueError.")
    _trigger_alert(
        f"Key generation failed after {retry_attempts} retries",
        AlertSeverity.ALERT_SEVERITY_CRITICAL,
    )
    raise ValueError("Failed to generate RSA key pair after retries") from last_exception



# 🔑 Key Serialization
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


# 🔓 Public Key Loading
def load_public_key(pem_data: bytes):
    """
    Load an RSA public key from PEM data.

    Args:
        pem_data (bytes): PEM-encoded public key.

    Returns:
        rsa.RSAPublicKey: Loaded RSA public key object.
    """
    try:
        return serialization.load_pem_public_key(pem_data, backend=default_backend())
    except Exception as e:
        logger.warning("Failed to load public key: %s", str(e))
        _trigger_alert("Public key load failed", AlertSeverity.ALERT_SEVERITY_WARNING)
        raise ValueError("Failed to load RSA public key") from e


# 🔄 Key Loading with Retry Logic
def load_private_key(pem_data: bytes, password: bytes = None, retry_attempts: int = 2):
    """
    Load an RSA private key from PEM data with retry logic.
    """
    last_exception = None  # Track the last encountered exception
    
    for attempt in range(retry_attempts):
        try:
            private_key = serialization.load_pem_private_key(pem_data, password=password)
            log_secure_action("Private key loaded successfully", {"protocol": "Seigr"})
            return private_key
        except Exception as e:
            last_exception = e
            logger.warning(
                "%s Attempt %d to load private key failed: %s",
                SEIGR_CELL_ID_PREFIX,
                attempt + 1,
                str(e),
            )
            if attempt == retry_attempts - 1:
                _trigger_alert(
                    "Private key load failed",
                    AlertSeverity.ALERT_SEVERITY_WARNING,
                )
        time.sleep(1)
    
    raise ValueError("Failed to load RSA private key") from last_exception


# 🔑 Sign Data with Validation and Enhanced Error Handling
def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Sign data using a private RSA key.

    Args:
        data (bytes): Data to be signed.
        private_key_pem (bytes): PEM-encoded private key.

    Returns:
        bytes: Digital signature of the data.

    Raises:
        ValueError: If the data is empty or key loading/signing fails.
    """
    # Validate input data
    if not data:
        raise ValueError("Cannot sign empty data.")

    try:
        # Load the private key using Seigr-native logic
        private_key = load_private_key(private_key_pem)
        
        # Log the signing action securely
        log_secure_action(
            "Signing data with private key.",
            {"data_length": len(data)},
        )
        
        # Sign the data using RSA and PSS padding
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        
        # Log successful signing
        logger.info(
            "%s Data signed successfully. Signature length: %d bytes",
            SEIGR_CELL_ID_PREFIX,
            len(signature)
        )
        
        return signature

    except Exception as e:
        logger.error(
            "%s Failed to sign data: %s",
            SEIGR_CELL_ID_PREFIX,
            str(e)
        )
        _trigger_alert(
            "Data signing failed due to an error.",
            AlertSeverity.ALERT_SEVERITY_CRITICAL
        )
        raise ValueError("Failed to sign data.") from e


# 🔑 Verify Signature
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a digital signature using the provided public key.

    Args:
        data (bytes): The original data.
        signature (bytes): The signature to verify.
        public_key_pem (bytes): PEM-encoded public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        logger.warning(
            "%s Signature verification failed: %s",
            SEIGR_CELL_ID_PREFIX,
            str(e),
        )
        error_log = ErrorLogEntry(
            error_id="signature_verification_failure",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="AsymmetricUtils",
            message="Signature verification failed",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE,
        )
        log_secure_action("Signature verification failure logged", {"error_id": error_log.error_id})
        return False
