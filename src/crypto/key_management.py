# src/crypto/key_management.py

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.secure_logging import SecureLogger
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
)

logger = logging.getLogger(__name__)
secure_logger = SecureLogger()


### 🛡️ Alert Trigger for Critical Key Management Issues ###


def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert for critical failures in key management.

    Args:
        message (str): Description of the issue.
        severity (AlertSeverity): Severity level of the alert.
    """
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_alert_{uuid.uuid4()}",
        message=message,
        type=AlertType.ALERT_TYPE_SECURITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="key_management",
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {severity.name}")


### 🔑 RSA Key Pair Generation ###


def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generates an RSA key pair.

    Args:
        key_size (int): The size of the RSA key to generate.

    Returns:
        Tuple[RSAPrivateKey, RSAPublicKey]: Private and public RSA keys.
    """
    try:
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Generating RSA key pair (key_size={key_size}).")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        public_key = private_key.public_key()
        logger.info(f"{SEIGR_CELL_ID_PREFIX} RSA key pair generated successfully.")
        return private_key, public_key
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_keypair_generation_fail",
            "Failed to generate RSA key pair.",
            e,
        )
        raise ValueError("RSA key pair generation failed.") from e


### 📦 Key Pair Serialization ###


def serialize_key_pair(
    private_key: RSAPrivateKey, public_key: RSAPublicKey, key_size: int
) -> AsymmetricKeyPair:
    """
    Serializes RSA key pair into an AsymmetricKeyPair protobuf.

    Args:
        private_key (RSAPrivateKey): Private RSA key.
        public_key (RSAPublicKey): Public RSA key.
        key_size (int): RSA key size.

    Returns:
        AsymmetricKeyPair: Protobuf object containing serialized key pair.
    """
    try:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        key_pair = AsymmetricKeyPair(
            key_pair_id=f"{SEIGR_CELL_ID_PREFIX}_key_{uuid.uuid4()}",
            public_key=public_pem,
            private_key=private_pem,
            algorithm=f"RSA-{key_size}",
            creation_timestamp=datetime.now(timezone.utc).isoformat(),
            lifecycle_status="active",
        )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} RSA key pair serialized successfully.")
        return key_pair
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_keypair_serialization_fail",
            "Failed to serialize RSA key pair.",
            e,
        )
        raise ValueError("Key pair serialization failed.") from e


### 💾 Key Pair Storage ###


def store_key_pair(key_pair: AsymmetricKeyPair, directory: str = "keys") -> None:
    """
    Stores RSA key pair in PEM files.

    Args:
        key_pair (AsymmetricKeyPair): Protobuf object with serialized keys.
        directory (str): Directory to store key files.
    """
    try:
        os.makedirs(directory, exist_ok=True)
        public_key_path = os.path.join(directory, f"{key_pair.key_pair_id}_public.pem")
        private_key_path = os.path.join(directory, f"{key_pair.key_pair_id}_private.pem")

        with open(public_key_path, "wb") as pub_file:
            pub_file.write(key_pair.public_key)

        with open(private_key_path, "wb") as priv_file:
            priv_file.write(key_pair.private_key)

        logger.info(f"{SEIGR_CELL_ID_PREFIX} Key pair stored successfully at {directory}.")
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_keypair_storage_fail",
            "Failed to store RSA key pair.",
            e,
        )
        raise


### 🔄 Key Rotation ###


def rotate_key_pair(
    existing_key_id: str, new_key_size: int = 2048, directory: str = "keys"
) -> AsymmetricKeyPair:
    """
    Rotates an existing RSA key pair.

    Args:
        existing_key_id (str): Existing key pair ID.
        new_key_size (int): New RSA key size.
        directory (str): Directory to store new key files.

    Returns:
        AsymmetricKeyPair: New RSA key pair protobuf object.
    """
    try:
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Rotating RSA key pair (ID={existing_key_id}).")
        private_key, public_key = generate_rsa_key_pair(new_key_size)
        new_key_pair = serialize_key_pair(private_key, public_key, new_key_size)
        store_key_pair(new_key_pair, directory)
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Key pair rotated successfully.")
        return new_key_pair
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_keypair_rotation_fail",
            "Failed to rotate RSA key pair.",
            e,
        )
        raise


### ⚠️ Error Logging ###


def _log_error(error_id, message, exception):
    error_log = ErrorLogEntry(
        error_id=error_id,
        severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
        component="Key Management",
        message=message,
        details=str(exception),
    )
    logger.error(f"{message}: {exception}")
