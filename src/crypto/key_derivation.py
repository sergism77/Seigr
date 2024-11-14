import logging
import os
import hashlib
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.helpers import encode_to_senary, apply_salt
from src.crypto.cbor_utils import encode_data as cbor_encode, decode_data as cbor_decode
from src.seigr_protocol.compiled.encryption_pb2 import SymmetricKey
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION

# Set up centralized logging for key derivation
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='seigr_key_derivation.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

### Key Derivation Functions ###

def generate_salt(length: int = 16) -> bytes:
    """Generates a cryptographic salt and logs its creation."""
    salt = os.urandom(length)
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated salt: {salt.hex()}")
    return salt

def derive_key(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32, use_senary: bool = True) -> str:
    """
    Derives a cryptographic key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting key derivation with password, iterations={iterations}, key_length={key_length}")
    try:
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=key_length)
        senary_key = encode_to_senary(key) if use_senary else key.hex()
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Derived key with PBKDF2, senary output={use_senary}")
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Derived key: {senary_key}")
        return senary_key
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_key_derivation_fail", "Failed to derive key", e)
        raise ValueError("Key derivation failed.") from e

def derive_hypha_key(data: str, salt: bytes = None, use_senary: bool = True) -> str:
    """
    Derives a secure key using Seigr's hypha hash, enabling traceable senary-based keys.
    """
    salt = salt or generate_salt()
    combined_data = (salt.hex() + data).encode()
    derived_key = HyphaCrypt.hash(combined_data, senary_output=use_senary)
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Derived hypha key with salt: {salt.hex()}")
    return derived_key

### Secure Key Storage and Retrieval ###

def store_key(key: bytes, filename: str, use_cbor: bool = True):
    """
    Stores a derived key in CBOR or binary format with error handling.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Storing key at {filename} in {'CBOR' if use_cbor else 'binary'} format")
    try:
        data_to_store = cbor_encode({'derived_key': key}) if use_cbor else key
        with open(filename, 'wb') as f:
            f.write(data_to_store)
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Derived key stored successfully at {filename}")
    except IOError as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_key_storage_fail", f"Failed to store key to {filename}", e)
        raise

def retrieve_key(filename: str, use_cbor: bool = True) -> bytes:
    """
    Retrieves a stored derived key from a file, optionally decoding CBOR format.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Retrieving key from {filename}")
    try:
        with open(filename, 'rb') as f:
            stored_data = f.read()
        if use_cbor:
            retrieved_data = cbor_decode(stored_data)
            key = retrieved_data.get('derived_key')
        else:
            key = stored_data
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Derived key retrieved successfully from {filename}")
        return key
    except IOError as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_key_retrieval_fail", f"Failed to retrieve key from {filename}", e)
        raise

### HMAC-Based Key Verification ###

def generate_hmac_key(data: bytes, key: bytes, use_senary: bool = True) -> str:
    """
    Generates an HMAC key from data and a base key using SHA-256.
    """
    hmac = hashlib.pbkdf2_hmac('sha256', data, key, 1)
    hmac_key = encode_to_senary(hmac) if use_senary else hmac.hex()
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated HMAC key: {hmac_key}")
    return hmac_key

def verify_hmac_key(data: bytes, expected_hmac: str, key: bytes, use_senary: bool = True) -> bool:
    """
    Verifies an HMAC key by comparing it with the expected HMAC.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Verifying HMAC key for data")
    actual_hmac = generate_hmac_key(data, key, use_senary=use_senary)
    match = actual_hmac == expected_hmac
    logger.info(f"{SEIGR_CELL_ID_PREFIX} HMAC verification result: {'Match' if match else 'No Match'} for expected HMAC.")
    return match

### Key Derivation Utilities for Protocol Buffer ###

def derive_key_to_protocol(password: str, salt: bytes = None, use_senary: bool = True) -> SymmetricKey:
    """
    Derives a key and outputs it as a protocol buffer message with metadata.
    """
    salt = salt or generate_salt()
    derived_key = derive_key(password, salt, use_senary=use_senary)
    symmetric_key = SymmetricKey(
        key_id=f"{SEIGR_CELL_ID_PREFIX}_derived_key",
        key=derived_key.encode(),
        salt=salt,
        algorithm="PBKDF2-HMAC-SHA256",
        creation_timestamp=datetime.now(timezone.utc).isoformat(),
        lifecycle_status="active",
        metadata={"encoding": "senary" if use_senary else "hex", "version": SEIGR_VERSION}
    )
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Derived key with protocol metadata: {symmetric_key}")
    return symmetric_key

### Helper Function for Error Logging ###

def _log_error(error_id, message, exception):
    """Logs an error using a structured protocol buffer entry."""
    error_log = ErrorLogEntry(
        error_id=error_id,
        severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
        component="Key Derivation",
        message=message,
        details=str(exception),
        resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
    )
    logger.error(f"{message}: {exception}")
