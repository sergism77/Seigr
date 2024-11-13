import logging
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair, SignatureLog
from src.crypto.encoding_utils import encode_to_senary

# Initialize the logger for the crypto module
logger = logging.getLogger(__name__)

### Key Generation ###

def generate_key_pair(key_size: int = 2048) -> AsymmetricKeyPair:
    """
    Generates an RSA public/private key pair and returns it in the AsymmetricKeyPair format.
    
    Args:
        key_size (int): The key size for the RSA key pair. Defaults to 2048.

    Returns:
        AsymmetricKeyPair: The generated public and private key pair with metadata.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    key_pair = AsymmetricKeyPair(
        key_pair_id=str(uuid.uuid4()),  # Generate a unique keypair ID
        public_key=serialize_public_key(public_key),
        private_key=serialize_private_key(private_key),
        algorithm=f"RSA-{key_size}",
        creation_timestamp=datetime.now(timezone.utc).isoformat(),
        lifecycle_status="active",
        metadata={"usage": "general"}
    )

    logger.info("Generated RSA key pair.")
    return key_pair

### Digital Signature ###

def sign_data(data: bytes, private_key_pem: bytes, use_senary: bool = True) -> SignatureLog:
    """
    Signs data using a private RSA key and returns a SignatureLog entry.
    
    Args:
        data (bytes): The data to be signed.
        private_key_pem (bytes): The private key in PEM format for signing.
        use_senary (bool): Whether to senary-encode the data hash.

    Returns:
        SignatureLog: Log of the digital signature operation.
    """
    private_key = load_private_key(private_key_pem)
    try:
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Generate and optionally encode data hash for logging
        data_hash = hashes.Hash(hashes.SHA256())
        data_hash.update(data)
        signed_data_hash = data_hash.finalize()
        if use_senary:
            signed_data_hash = encode_to_senary(signed_data_hash)

        signature_log = SignatureLog(
            log_id=str(uuid.uuid4()),
            signer_id="signer_identifier",
            signature=signature,
            signing_algorithm="RSA-SHA256",
            signed_data_hash=signed_data_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={"context": "sample_signing_operation"}
        )
        logger.debug("Data signed using RSA private key.")
        return signature_log
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="signing_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Crypto",
            message="Data signing failed",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(f"Signing failed: {error_log.message}")
        raise ValueError(error_log.message)

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verifies a digital signature using a public RSA key.
    
    Args:
        data (bytes): The original data that was signed.
        signature (bytes): The digital signature to verify.
        public_key_pem (bytes): The public key in PEM format for verification.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.debug("Signature verified successfully.")
        return True
    except InvalidSignature:
        error_log = ErrorLogEntry(
            error_id="sig_verification_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Crypto",
            message="Signature verification failed",
            details="The provided signature did not match the data.",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.warning(f"Signature verification failed: {error_log.message}")
        return False

### Key Serialization and Deserialization ###

def serialize_public_key(public_key) -> bytes:
    """Serializes a public RSA key to PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug("Serialized RSA public key to PEM format.")
    return pem

def serialize_private_key(private_key) -> bytes:
    """Serializes a private RSA key to PEM format."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    logger.debug("Serialized RSA private key to PEM format.")
    return pem

def load_public_key(pem_data: bytes):
    """Loads a public RSA key from PEM format."""
    try:
        public_key = serialization.load_pem_public_key(pem_data)
        logger.debug("Loaded RSA public key from PEM format.")
        return public_key
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="pub_key_load_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="Crypto",
            message="Failed to load RSA public key from PEM",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_RETRY
        )
        logger.error(f"Public key loading failed: {error_log.details}")
        raise

def load_private_key(pem_data: bytes):
    """Loads a private RSA key from PEM format."""
    try:
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        logger.debug("Loaded RSA private key from PEM format.")
        return private_key
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="priv_key_load_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="Crypto",
            message="Failed to load RSA private key from PEM",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_RETRY
        )
        logger.error(f"Private key loading failed: {error_log.details}")
        raise
