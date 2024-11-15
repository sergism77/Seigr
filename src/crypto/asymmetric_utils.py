import logging
import uuid
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair, SignatureLog
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.key_management import generate_rsa_key_pair
from src.crypto.secure_logging import log_secure_action
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

# Initialize the logger for the crypto module
logger = logging.getLogger(__name__)

### Key Generation with Enhanced Error Reporting ###

def generate_key_pair(key_size: int = 2048, retry_attempts: int = 3) -> AsymmetricKeyPair:
    """Generates an RSA key pair with enhanced error resilience, eco-efficiency, and retry logic."""
    for attempt in range(retry_attempts):
        try:
            # Dynamically adjust key size if provided for eco-efficiency
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
                    "rotation_policy": "annual",  # Added rotation policy metadata
                    "expected_duration": "1 year"
                }
            )
            log_secure_action("Key pair generated", {"key_size": key_size, "key_pair_id": key_pair.key_pair_id})
            return key_pair
        except Exception as e:
            logger.warning(f"Key generation attempt {attempt + 1} failed: {str(e)}")
            if attempt == retry_attempts - 1:
                _trigger_alert("Key generation failed after retries", AlertSeverity.CRITICAL)
                raise ValueError("Failed to generate RSA key pair after retries") from e
            time.sleep(2 ** attempt)  # Exponential backoff for retries

### Digital Signature ###

def sign_data(data: bytes, private_key_pem: bytes, use_senary: bool = True, hash_algorithm=hashes.SHA256) -> SignatureLog:
    """Signs data using RSA and logs for Seigr traceability."""
    private_key = load_private_key(private_key_pem)
    try:
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hash_algorithm()), salt_length=padding.PSS.MAX_LENGTH),
            hash_algorithm()
        )
        
        data_hash = hashes.Hash(hash_algorithm())
        data_hash.update(data)
        signed_data_hash = data_hash.finalize()
        signed_data_hash = encode_to_senary(signed_data_hash) if use_senary else signed_data_hash

        signature_log = SignatureLog(
            log_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
            signer_id="signer_identifier",
            signature=signature,
            signing_algorithm="RSA-SHA256",
            signed_data_hash=signed_data_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={
                "context": "sample_signing_operation",
                "seigr_protocol": "active",
                "data_type": "general"
            }
        )
        log_secure_action("Data signed", {"log_id": signature_log.log_id, "algorithm": "RSA-SHA256"})
        return signature_log
    except Exception as e:
        logger.error(f"Signing failed: {str(e)}")
        _trigger_alert("Signing operation failed", AlertSeverity.HIGH)
        raise ValueError("Data signing failed") from e

### Key Verification ###

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verifies a digital signature and logs verification status for Seigr traceability."""
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        log_secure_action("Signature verified", {"data": encode_to_senary(data[:10]), "result": True})
        return True
    except InvalidSignature:
        log_secure_action("Signature verification failed", {"data": encode_to_senary(data[:10]), "result": False})
        return False

### Serialization Functions with Rotation Preparation ###

def serialize_public_key(public_key) -> bytes:
    """Serializes a public RSA key with Seigr protocol logging."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    log_secure_action("Public key serialized", {"protocol": "Seigr"})
    return pem

def serialize_private_key(private_key, encryption_password: bytes = None) -> bytes:
    """Serializes a private RSA key with Seigr logging for rotation support."""
    encryption_algo = (
        serialization.BestAvailableEncryption(encryption_password) if encryption_password
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )
    log_secure_action("Private key serialized", {"protocol": "Seigr"})
    return pem

### Load and Error-Resilient Retry Logic ###

def load_public_key(pem_data: bytes, retry_attempts: int = 2):
    """Loads a public RSA key with retry logic and Seigr logging."""
    for attempt in range(retry_attempts):
        try:
            public_key = serialization.load_pem_public_key(pem_data)
            log_secure_action("Public key loaded", {"protocol": "Seigr"})
            return public_key
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} to load public key failed: {str(e)}")
            if attempt == retry_attempts - 1:
                _trigger_alert("Public key load failed", AlertSeverity.MEDIUM)
                raise ValueError("Failed to load RSA public key") from e
            time.sleep(2 ** attempt)  # Exponential backoff

def load_private_key(pem_data: bytes, retry_attempts: int = 2):
    """Loads a private RSA key with retry logic and Seigr logging."""
    for attempt in range(retry_attempts):
        try:
            private_key = serialization.load_pem_private_key(pem_data, password=None)
            log_secure_action("Private key loaded", {"protocol": "Seigr"})
            return private_key
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} to load private key failed: {str(e)}")
            if attempt == retry_attempts - 1:
                _trigger_alert("Private key load failed", AlertSeverity.MEDIUM)
                raise ValueError("Failed to load RSA private key") from e
            time.sleep(2 ** attempt)  # Exponential backoff

### Alert Trigger for High-Severity Events ###

def _trigger_alert(message: str, severity: AlertSeverity, recipient_id: str = None) -> None:
    """Triggers an alert for high-severity cryptographic issues."""
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        message=message,
        alert_type=AlertType.SECURITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        recipient_id=recipient_id
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {alert.severity.name}")
