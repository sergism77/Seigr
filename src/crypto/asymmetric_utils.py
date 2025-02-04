"""
📌 **Seigr Asymmetric Utilities Module**
Handles asymmetric encryption, key pair generation,
and digital signatures in compliance with **Seigr cryptographic protocols**.
"""

import time
import logging
import uuid
from collections import namedtuple
from typing import Tuple, Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from google.protobuf.timestamp_pb2 import Timestamp  # ✅ Correct Timestamp Usage

# 🔐 Seigr Imports
from src.crypto.key_management import generate_rsa_key_pair
from src.logger.secure_logger import secure_logger
from src.crypto.alert_utils import trigger_alert
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct import
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)  # ✅ Keep only necessary imports
from src.utils.timestamp_utils import get_current_protobuf_timestamp

# 🛠️ Define RSA KeyPair named tuple for clarity
RSAKeyPair = namedtuple("RSAKeyPair", ["private_key", "public_key"])

# Logger initialization
logger = logging.getLogger(__name__)


# ===============================
# 🔑 **RSA Key Generation**
# ===============================
def generate_key_pair(
    key_size: int = 2048, retry_attempts: int = 3, retry_delay: int = 2
) -> RSAKeyPair:
    """
    **Generates an RSA key pair with retry logic and structured error handling.**
    """
    last_exception = None

    for attempt in range(retry_attempts):
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Key Management",  # ✅ CORRECT CATEGORY
            message="Failed to generate RSA key pair after retries.",
            sensitive=False,
            use_senary=False,
        )

        try:
            private_key, public_key = generate_rsa_key_pair(key_size)
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Key Management",
                message="✅ RSA Key Pair generated successfully.",
            )
            return RSAKeyPair(private_key=private_key, public_key=public_key)
        except Exception as e:
            last_exception = e
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="Key Management",
                message=f"⚠️ Attempt {attempt + 1} failed: {e}",
            )
            if attempt < retry_attempts - 1:
                time.sleep(retry_delay)

    trigger_alert(
        message="Failed to generate RSA key pair after retries.",
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        alert_type=AlertType.ALERT_TYPE_SECURITY,
        source_component="asymmetric_utils",
    )

    raise ValueError("Failed to generate RSA key pair after retries.") from last_exception


# ===============================
# 🔏 **Key Serialization & Loading**
# ===============================
def serialize_private_key(
    private_key: rsa.RSAPrivateKey, encryption_password: Optional[bytes] = None
) -> bytes:
    """
    **Serializes an RSA private key to PEM format with optional encryption.**
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


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    **Serializes an RSA public key to PEM format.**
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(
    pem_data: bytes, password: Optional[bytes] = None, retry_attempts: int = 3
) -> rsa.RSAPrivateKey:
    """
    **Loads an RSA private key from PEM data, with retry logic.**
    """
    last_exception = None

    for attempt in range(retry_attempts):
        try:
            return serialization.load_pem_private_key(
                pem_data, password=password, backend=default_backend()
            )
        except Exception as e:
            last_exception = e
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="Key Management",
                message=f"Private key load failed (Attempt {attempt + 1}/{retry_attempts})",
                sensitive=False,
                use_senary=False,
            )
            if attempt < retry_attempts - 1:
                time.sleep(1)

    trigger_alert(
        message="Private key load failed after retries.",
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        alert_type=AlertType.ALERT_TYPE_SECURITY,
        source_component="asymmetric_utils",
    )

    raise ValueError("Failed to load RSA private key.") from last_exception


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    **Loads an RSA public key from PEM data.**
    """
    try:
        return serialization.load_pem_public_key(pem_data, backend=default_backend())
    except Exception as e:
        trigger_alert(
            message="Public key load failed.",
            severity=AlertSeverity.ALERT_SEVERITY_WARNING,
            alert_type=AlertType.ALERT_TYPE_SECURITY,
            source_component="asymmetric_utils",
        )

        raise ValueError("Failed to load RSA public key.") from e


# ===============================
# 🔏 **Data Signing & Verification**
# ===============================
def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    **Signs data using an RSA private key.**
    """
    if not data:  # ✅ Ensure empty data cannot be signed
        raise ValueError("Cannot sign empty data.")

    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    **Verifies a digital signature using an RSA public key.**
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
