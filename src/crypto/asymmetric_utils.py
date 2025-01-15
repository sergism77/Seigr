"""
Asymmetric Utilities Module

Provides functionality for asymmetric encryption, key pair generation,
and digital signatures in accordance with Seigr protocols.
"""

import logging
import time
from collections import namedtuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Local imports
from src.crypto.key_management import generate_rsa_key_pair
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity

# Define RSAKeyPair for clarity
RSAKeyPair = namedtuple("RSAKeyPair", ["private_key", "public_key"])

logger = logging.getLogger(__name__)


# 🛡️ Alert Trigger for High-Severity Events
def _trigger_alert(message: str, severity: AlertSeverity, category: str = "Security") -> None:
    """
    Trigger a structured alert using SecureLogger.
    """
    secure_logger.log_audit_event(
        severity=severity, category=category, message=message, sensitive=False, use_senary=False
    )


# 🗝️ Key Generation with Retry Logic
def generate_key_pair(
    key_size: int = 2048, retry_attempts: int = 3, retry_delay: int = 2
) -> RSAKeyPair:
    """
    Generate an RSA key pair with retry logic and structured error handling.
    """
    last_exception = None

    for attempt in range(retry_attempts):
        logger.debug("Attempt %d to generate RSA key pair.", attempt + 1)
        print(f"Attempt {attempt + 1} to generate RSA key pair.")
        try:
            private_key, public_key = generate_rsa_key_pair(key_size)
            print("Key generation succeeded.")
            return RSAKeyPair(private_key=private_key, public_key=public_key)
        except Exception as e:
            last_exception = e
            print(f"Attempt {attempt + 1} failed with exception: {e}")
            logger.warning("Attempt %d failed: %s", attempt + 1, str(e))
            if attempt < retry_attempts - 1:
                print("Retrying after delay...")
                time.sleep(retry_delay)

    print("All retries exhausted. Triggering alert and raising ValueError.")
    logger.critical("All retries exhausted. Raising ValueError now.")
    _trigger_alert(
        "Key generation failed after retries",
        AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Key Management",
    )
    print("Raising ValueError now.")
    raise ValueError(
        f"Failed to generate RSA key pair after retries. Last exception: {last_exception}"
    ) from last_exception


# 🔑 Serialize Public Key
def serialize_public_key(public_key) -> bytes:
    """
    Serialize an RSA public key to PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# 🔑 Serialize Private Key
def serialize_private_key(private_key, encryption_password: bytes = None) -> bytes:
    """
    Serialize an RSA private key to PEM format.
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


# 🔓 Load Private Key with Retry Logic
def load_private_key(pem_data: bytes, password: bytes = None, retry_attempts: int = 2):
    """
    Load an RSA private key from PEM data with retry logic.
    """
    last_exception = None

    for attempt in range(retry_attempts):
        try:
            logger.info("Attempt %d to load private key.", attempt + 1)
            private_key = serialization.load_pem_private_key(pem_data, password=password)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Key Management",
                message="Private key loaded successfully",
                sensitive=False,
                use_senary=False,
            )

            return private_key

        except (ValueError, TypeError) as e:
            last_exception = e
            logger.warning("Attempt %d to load private key failed: %s", attempt + 1, str(e))
        except Exception as e:
            last_exception = e
            logger.warning("Unexpected error in private key loading: %s", str(e))

        time.sleep(1)

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_WARNING,
        category="Key Management",
        message="Private key load failed",
        sensitive=False,
        use_senary=False,
    )
    raise ValueError("Failed to load RSA private key after retries") from last_exception


# 🔓 Load Public Key
def load_public_key(pem_data: bytes):
    """
    Load an RSA public key from PEM data.
    """
    try:
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        logger.info("Public key loaded successfully.")
        return public_key
    except Exception as e:
        logger.warning("Failed to load public key: %s", str(e))
        _trigger_alert(
            "Public key load failed", AlertSeverity.ALERT_SEVERITY_WARNING, category="Security"
        )
        raise ValueError("Failed to load RSA public key") from e


# 🔑 Sign Data with Validation
def sign_data(data: bytes, private_key) -> bytes:
    """
    Sign data using a private RSA key.
    """
    if not data:
        raise ValueError("Cannot sign empty data.")

    try:
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        logger.info("Data signed successfully.")
        return signature
    except Exception as e:
        logger.error("Failed to sign data: %s", str(e))
        _trigger_alert(
            "Data signing failed", AlertSeverity.ALERT_SEVERITY_CRITICAL, category="Security"
        )
        raise ValueError("Failed to sign data.") from e


# ✅ Verify Signature
def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify a digital signature using a public RSA key.
    """
    if not data or not signature:
        logger.warning("Empty data or signature provided for verification.")
        return False  # Changed from raising ValueError to returning False

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        logger.info("Signature successfully verified.")
        return True
    except Exception as e:
        logger.warning("Signature verification failed: %s", str(e))
        _trigger_alert(
            "Signature verification failed",
            AlertSeverity.ALERT_SEVERITY_WARNING,
            category="Key Management",
        )
        return False
