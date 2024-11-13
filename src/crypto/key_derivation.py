import logging
import os
import hashlib
from datetime import datetime, timezone
from src.crypto.hash_utils import hypha_hash
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.cbor_utils import encode_data as cbor_encode, decode_data as cbor_decode
from src.seigr_protocol.compiled.encryption_pb2 import SymmetricKey
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

# Set up centralized logging for key derivation
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='seigr_key_derivation.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

### Key Derivation Functions ###

def generate_salt(length: int = 16) -> bytes:
    """Generates a cryptographic salt."""
    salt = os.urandom(length)
    logger.debug(f"Generated salt: {salt.hex()}")
    return salt

def derive_key(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32, use_senary: bool = True) -> str:
    """
    Derives a cryptographic key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    try:
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=key_length)
        logger.info(f"Derived key with PBKDF2: iterations={iterations}, key_length={key_length}")
        senary_key = encode_to_senary(key) if use_senary else key.hex()
        logger.debug(f"Derived key: {senary_key}")
        return senary_key
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="key_derivation_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Key Derivation",
            message="Failed to derive key",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError(error_log.message) from e

def derive_hypha_key(data: str, salt: bytes = None, use_senary: bool = True) -> str:
    """
    Derives a secure key based on the Seigr-specific hypha hash, enabling traceable and senary-based keys.
    """
    salt = salt or generate_salt()
    combined_data = (salt.hex() + data).encode()
    derived_key = hypha_hash(combined_data, senary_output=use_senary)
    logger.debug(f"Derived hypha key for data with salt: {salt.hex()}")
    return derived_key

### Secure Key Storage and Retrieval ###

def store_key(key: bytes, filename: str, use_cbor: bool = True):
    """
    Stores a derived key in CBOR or binary format.
    """
    try:
        data_to_store = cbor_encode({'derived_key': key}) if use_cbor else key
        with open(filename, 'wb') as f:
            f.write(data_to_store)
        logger.info(f"Derived key stored in {'CBOR' if use_cbor else 'binary'} format at {filename}.")
    except IOError as e:
        error_log = ErrorLogEntry(
            error_id="key_storage_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="Key Storage",
            message=f"Failed to store key to {filename}",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_RETRY
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise

def retrieve_key(filename: str, use_cbor: bool = True) -> bytes:
    """
    Retrieves a stored derived key from a file.
    """
    try:
        with open(filename, 'rb') as f:
            stored_data = f.read()
        if use_cbor:
            retrieved_data = cbor_decode(stored_data)
            key = retrieved_data.get('derived_key')
        else:
            key = stored_data
        logger.info(f"Derived key retrieved from {filename}.")
        return key
    except IOError as e:
        error_log = ErrorLogEntry(
            error_id="key_retrieval_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="Key Retrieval",
            message=f"Failed to retrieve key from {filename}",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_RETRY
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise

### HMAC-Based Key Verification ###

def generate_hmac_key(data: bytes, key: bytes, use_senary: bool = True) -> str:
    """
    Generates an HMAC key from data and a base key using SHA-256.
    """
    hmac = hashlib.pbkdf2_hmac('sha256', data, key, 1)  # One iteration for HMAC simulation
    hmac_key = encode_to_senary(hmac) if use_senary else hmac.hex()
    logger.debug(f"Generated HMAC key: {hmac_key}")
    return hmac_key

def verify_hmac_key(data: bytes, expected_hmac: str, key: bytes, use_senary: bool = True) -> bool:
    """
    Verifies an HMAC key by comparing it with the expected HMAC.
    """
    actual_hmac = generate_hmac_key(data, key, use_senary=use_senary)
    match = actual_hmac == expected_hmac
    logger.info(f"HMAC verification result: {'Match' if match else 'No Match'} for data with expected HMAC.")
    return match

### Key Derivation Utilities for Protocol Buffer ###

def derive_key_to_protocol(password: str, salt: bytes = None, use_senary: bool = True) -> SymmetricKey:
    """
    Derives a key and outputs it as a protocol buffer message with metadata.
    """
    salt = salt or generate_salt()
    derived_key = derive_key(password, salt, use_senary=use_senary)
    symmetric_key = SymmetricKey(
        key_id="derived_key",
        key=derived_key.encode(),
        salt=salt,
        algorithm="PBKDF2-HMAC-SHA256",
        creation_timestamp=datetime.now(timezone.utc).isoformat(),
        lifecycle_status="active",
        metadata={"encoding": "senary" if use_senary else "hex"}
    )
    logger.debug(f"Derived key with protocol metadata: {symmetric_key}")
    return symmetric_key
