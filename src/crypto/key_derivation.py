"""
Module: key_derivation.py

This module handles cryptographic key derivation, secure key storage,
HMAC-based verification, and error logging. It ensures adherence to Seigr's
cryptographic standards.
"""

import hashlib
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.crypto.constants import SALT_SIZE, SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import encode_to_senary

logger = logging.getLogger(__name__)

### 🔑 Key Derivation Utilities ###


def generate_salt(length: int = SALT_SIZE) -> bytes:
    """
    Generates a cryptographic salt.

    Args:
        length (int): Length of the salt in bytes.

    Returns:
        bytes: Generated salt.
    """
    salt = os.urandom(length)
    logger.debug("%s Generated salt: %s", SEIGR_CELL_ID_PREFIX, salt.hex())
    return salt


def derive_key_from_password(
    password: str, salt: bytes = None, length: int = 32, iterations: int = 100000
) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password (str): Password for key derivation.
        salt (bytes): Salt for PBKDF2. Generates a new one if None.
        length (int): Length of the derived key.
        iterations (int): Number of iterations for PBKDF2.

    Returns:
        bytes: Derived key in binary format.
    """
    salt = salt or generate_salt()
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        logger.debug(
            "%s Derived binary key using PBKDF2 with salt: %s",
            SEIGR_CELL_ID_PREFIX,
            salt.hex(),
        )
        return key
    except Exception as e:
        logger.error("%s Failed to derive key from password: %s", SEIGR_CELL_ID_PREFIX, e)
        raise ValueError("Key derivation from password failed.") from e


def derive_key(
    password: str,
    salt: bytes,
    iterations: int = 100000,
    key_length: int = 32,
    use_senary: bool = True,
) -> str:
    """
    Derives a cryptographic key and optionally encodes it to senary format.

    Args:
        password (str): Password for key derivation.
        salt (bytes): Salt value.
        iterations (int): Number of PBKDF2 iterations.
        key_length (int): Length of the derived key.
        use_senary (bool): Whether to encode the key in senary format.

    Returns:
        str: Derived key in senary or hexadecimal format.
    """
    binary_key = derive_key_from_password(password, salt, length=key_length, iterations=iterations)
    senary_key = encode_to_senary(binary_key) if use_senary else binary_key.hex()
    logger.debug("%s Key derivation successful.", SEIGR_CELL_ID_PREFIX)
    return senary_key


### 📥 Secure Key Storage and Retrieval ###


def store_key(key: bytes, filename: str):
    """
    Stores a derived key in binary format with error handling.

    Args:
        key (bytes): The cryptographic key to store.
        filename (str): Path to the file where the key will be saved.
    """
    try:
        with open(filename, "wb") as f:
            f.write(key)
        logger.info("%s Derived key stored successfully at %s", SEIGR_CELL_ID_PREFIX, filename)
    except IOError as e:
        logger.error("%s Failed to store key to %s: %s", SEIGR_CELL_ID_PREFIX, filename, e)
        raise


def retrieve_key(filename: str) -> bytes:
    """
    Retrieves a stored derived key from a file.

    Args:
        filename (str): Path to the file storing the key.

    Returns:
        bytes: The retrieved cryptographic key.
    """
    try:
        with open(filename, "rb") as f:
            key = f.read()
        logger.info("%s Derived key retrieved successfully from %s", SEIGR_CELL_ID_PREFIX, filename)
        return key
    except IOError as e:
        logger.error("%s Failed to retrieve key from %s: %s", SEIGR_CELL_ID_PREFIX, filename, e)
        raise


### 🔑 HMAC-Based Key Verification ###


def generate_hmac_key(data: bytes, key: bytes, use_senary: bool = True) -> str:
    """
    Generates an HMAC key using SHA-256.

    Args:
        data (bytes): Data to hash.
        key (bytes): Key for HMAC.
        use_senary (bool): Whether to encode the result in senary.

    Returns:
        str: HMAC key in senary or hexadecimal format.
    """
    hmac = hashlib.pbkdf2_hmac("sha256", data, key, 1)
    hmac_key = encode_to_senary(hmac) if use_senary else hmac.hex()
    logger.debug("%s Generated HMAC key: %s", SEIGR_CELL_ID_PREFIX, hmac_key)
    return hmac_key


def verify_hmac_key(data: bytes, expected_hmac: str, key: bytes, use_senary: bool = True) -> bool:
    """
    Verifies an HMAC key.

    Args:
        data (bytes): Original data.
        expected_hmac (str): Expected HMAC value.
        key (bytes): Key for HMAC.

    Returns:
        bool: True if the HMAC matches, False otherwise.
    """
    actual_hmac = generate_hmac_key(data, key, use_senary=use_senary)
    match = actual_hmac == expected_hmac
    logger.info(
        "%s HMAC verification result: %s",
        SEIGR_CELL_ID_PREFIX,
        "Match" if match else "No Match",
    )
    return match
