# src/crypto/asymmetric_utils.py

import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Initialize the logger for the crypto module
logger = logging.getLogger(__name__)

def generate_key_pair(key_size: int = 2048):
    """
    Generates an RSA public/private key pair.
    
    Args:
        key_size (int): The key size for the RSA key pair. Defaults to 2048.

    Returns:
        tuple: A tuple containing the public key and private key in PEM format (bytes).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    logger.info("Generated RSA key pair.")
    return public_key_pem, private_key_pem

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Signs data using a private RSA key.
    
    Args:
        data (bytes): The data to be signed.
        private_key_pem (bytes): The private key in PEM format for signing.

    Returns:
        bytes: The digital signature of the data.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    logger.debug("Data signed using RSA private key.")
    return signature

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
    public_key = serialization.load_pem_public_key(public_key_pem)
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
        logger.warning("Signature verification failed.")
        return False

def serialize_public_key(public_key) -> bytes:
    """
    Serializes a public RSA key to PEM format.
    
    Args:
        public_key: The RSA public key object.

    Returns:
        bytes: The serialized public key in PEM format.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug("Serialized RSA public key to PEM format.")
    return pem

def serialize_private_key(private_key) -> bytes:
    """
    Serializes a private RSA key to PEM format.
    
    Args:
        private_key: The RSA private key object.

    Returns:
        bytes: The serialized private key in PEM format.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    logger.debug("Serialized RSA private key to PEM format.")
    return pem

def load_public_key(pem_data: bytes):
    """
    Loads a public RSA key from PEM format.
    
    Args:
        pem_data (bytes): The public key in PEM format.

    Returns:
        public_key: The deserialized RSA public key object.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    logger.debug("Loaded RSA public key from PEM format.")
    return public_key

def load_private_key(pem_data: bytes):
    """
    Loads a private RSA key from PEM format.
    
    Args:
        pem_data (bytes): The private key in PEM format.

    Returns:
        private_key: The deserialized RSA private key object.
    """
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    logger.debug("Loaded RSA private key from PEM format.")
    return private_key
