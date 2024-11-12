# src/crypto/key_derivation.py

import logging
import os
import hashlib
from src.crypto.hash_utils import hypha_hash
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.cbor_utils import cbor_encode, cbor_decode

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

    Args:
        password (str): The password to derive the key from.
        salt (bytes): Salt to add randomness to the key derivation.
        iterations (int): Number of iterations for PBKDF2 (default is 100,000).
        key_length (int): Desired length of the derived key (in bytes).
        use_senary (bool): Outputs the derived key as senary-encoded if True.

    Returns:
        str: The derived key, senary-encoded if specified.
    """
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=key_length)
    logger.info(f"Derived key using PBKDF2 with {iterations} iterations and key length of {key_length} bytes.")
    
    if use_senary:
        senary_key = encode_to_senary(key)
        logger.debug(f"Senary-encoded derived key: {senary_key}")
        return senary_key
    else:
        return key.hex()

def derive_hypha_key(data: str, salt: bytes = None, use_senary: bool = True) -> str:
    """
    Derives a secure key based on the Seigr-specific hypha hash, enabling traceable and senary-based keys.

    Args:
        data (str): The data to be used as input for the key derivation.
        salt (bytes): Optional salt to apply. If None, a random salt is generated.
        use_senary (bool): Outputs the derived key as senary-encoded if True.

    Returns:
        str: The derived key, senary-encoded if specified.
    """
    salt = salt or generate_salt()
    combined_data = (salt.hex() + data).encode()
    derived_key = hypha_hash(combined_data, senary_output=use_senary)
    logger.debug(f"Derived hypha key for data with salt {salt.hex()}.")

    return derived_key

### Secure Key Storage and Retrieval ###

def store_key(key: bytes, filename: str, use_cbor: bool = True):
    """
    Stores a derived key in CBOR or binary format.

    Args:
        key (bytes): The derived key to store.
        filename (str): Path to the file where the key will be stored.
        use_cbor (bool): Stores as CBOR if True, otherwise as binary.
    """
    data_to_store = cbor_encode({'derived_key': key}) if use_cbor else key
    with open(filename, 'wb') as f:
        f.write(data_to_store)
    logger.info(f"Derived key stored in {'CBOR' if use_cbor else 'binary'} format at {filename}.")

def retrieve_key(filename: str, use_cbor: bool = True) -> bytes:
    """
    Retrieves a stored derived key from a file.

    Args:
        filename (str): Path to the file from which the key will be retrieved.
        use_cbor (bool): Reads as CBOR if True, otherwise as binary.

    Returns:
        bytes: The retrieved key.
    """
    with open(filename, 'rb') as f:
        stored_data = f.read()

    if use_cbor:
        retrieved_data = cbor_decode(stored_data)
        key = retrieved_data.get('derived_key', None)
    else:
        key = stored_data

    logger.info(f"Derived key retrieved from {filename}.")
    return key

### HMAC-Based Key Verification ###

def generate_hmac_key(data: bytes, key: bytes, use_senary: bool = True) -> str:
    """
    Generates an HMAC key from data and a base key using SHA-256.

    Args:
        data (bytes): Data to authenticate with HMAC.
        key (bytes): Base key for HMAC generation.
        use_senary (bool): Returns senary-encoded HMAC if True.

    Returns:
        str: The HMAC key, senary-encoded if specified.
    """
    hmac = hashlib.pbkdf2_hmac('sha256', data, key, 1)  # One iteration for HMAC simulation
    hmac_key = encode_to_senary(hmac) if use_senary else hmac.hex()
    logger.debug(f"Generated HMAC key: {hmac_key}")
    return hmac_key

def verify_hmac_key(data: bytes, expected_hmac: str, key: bytes, use_senary: bool = True) -> bool:
    """
    Verifies an HMAC key by comparing it with the expected HMAC.

    Args:
        data (bytes): Data to authenticate with HMAC.
        expected_hmac (str): Expected HMAC to compare against.
        key (bytes): Base key for HMAC generation.
        use_senary (bool): True if expected HMAC is senary-encoded.

    Returns:
        bool: True if the generated HMAC matches the expected HMAC, False otherwise.
    """
    actual_hmac = generate_hmac_key(data, key, use_senary=use_senary)
    match = actual_hmac == expected_hmac
    logger.info(f"HMAC verification result: {'Match' if match else 'No Match'}.")
    return match

### Key Derivation Utilities for Protocol Buffer ###

def derive_key_to_protocol(password: str, salt: bytes = None, use_senary: bool = True) -> dict:
    """
    Derives a key and outputs it in a protocol-compatible format with metadata.

    Args:
        password (str): Password to derive the key from.
        salt (bytes): Optional salt; if None, a new salt is generated.
        use_senary (bool): Outputs the key as senary-encoded if True.

    Returns:
        dict: A dictionary with derived key and metadata for protocol compatibility.
    """
    salt = salt or generate_salt()
    derived_key = derive_key(password, salt, use_senary=use_senary)
    key_metadata = {
        'derived_key': derived_key,
        'salt': encode_to_senary(salt) if use_senary else salt.hex(),
        'encoding': 'senary' if use_senary else 'hex'
    }
    logger.debug(f"Derived key with protocol metadata: {key_metadata}")
    return key_metadata
