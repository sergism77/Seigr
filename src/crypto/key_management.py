import logging
import os
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from datetime import datetime, timezone
from src.seigr_protocol.compiled.encryption_pb2 import AsymmetricKeyPair
from src.crypto.helpers import encode_to_senary
from src.crypto.secure_logging import SecureLogger
from src.seigr_protocol.compiled.audit_logging_pb2 import LogLevel, LogCategory

# Initialize logger for key management
logger = logging.getLogger(__name__)
secure_logger = SecureLogger()

def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generates an RSA key pair with a specified key size and returns the private and public keys.

    Args:
        key_size (int): The size of the RSA key to generate. Defaults to 2048 bits.

    Returns:
        Tuple[RSAPrivateKey, RSAPublicKey]: The generated private and public keys.
    """
    logger.info("Generating RSA key pair.")
    
    # Generate the RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    logger.info("RSA key pair generated successfully.")
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_INFO,
        category=LogCategory.LOG_CATEGORY_SECURITY,
        message="RSA key pair generated.",
        sensitive=True
    )

    return private_key, public_key

def serialize_key_pair(private_key: RSAPrivateKey, public_key: RSAPublicKey, key_size: int) -> AsymmetricKeyPair:
    """
    Serializes the RSA private and public keys into an AsymmetricKeyPair protobuf message.

    Args:
        private_key (RSAPrivateKey): The private RSA key to serialize.
        public_key (RSAPublicKey): The public RSA key to serialize.
        key_size (int): The size of the RSA key.

    Returns:
        AsymmetricKeyPair: Protobuf message containing the serialized RSA key pair.
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_pair = AsymmetricKeyPair(
        key_pair_id=f"key_{datetime.now(timezone.utc).isoformat()}",
        public_key=public_pem,
        private_key=private_pem,
        algorithm=f"RSA-{key_size}",
        creation_timestamp=datetime.now(timezone.utc).isoformat(),
        lifecycle_status="active"
    )
    
    return key_pair

def store_key_pair(key_pair: AsymmetricKeyPair, directory: str = "keys") -> None:
    """
    Stores an RSA key pair in separate files for the private and public keys.

    Args:
        key_pair (AsymmetricKeyPair): Protobuf message containing the RSA key pair.
        directory (str): Directory to store the key files. Defaults to "keys".
    """
    os.makedirs(directory, exist_ok=True)

    public_key_path = os.path.join(directory, f"{key_pair.key_pair_id}_public.pem")
    private_key_path = os.path.join(directory, f"{key_pair.key_pair_id}_private.pem")

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(key_pair.public_key)

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(key_pair.private_key)

    logger.info(f"Stored key pair with ID {key_pair.key_pair_id} at {directory}.")

def load_private_key(file_path: str) -> RSAPrivateKey:
    """
    Loads a private RSA key from a PEM file.

    Args:
        file_path (str): Path to the private key PEM file.

    Returns:
        RSAPrivateKey: The private RSA key.
    """
    with open(file_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )
    logger.info(f"Private key loaded from {file_path}.")
    return private_key

def load_public_key(file_path: str) -> RSAPublicKey:
    """
    Loads a public RSA key from a PEM file.

    Args:
        file_path (str): Path to the public key PEM file.

    Returns:
        RSAPublicKey: The public RSA key.
    """
    with open(file_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    logger.info(f"Public key loaded from {file_path}.")
    return public_key

def rotate_key_pair(existing_key_id: str, new_key_size: int = 2048, directory: str = "keys") -> AsymmetricKeyPair:
    """
    Rotates an RSA key pair by generating a new key pair and storing it with a new key ID.

    Args:
        existing_key_id (str): The ID of the existing key pair to rotate.
        new_key_size (int): The size of the new RSA key. Defaults to 2048 bits.
        directory (str): Directory to store the new key files.

    Returns:
        AsymmetricKeyPair: Protobuf message containing the newly generated RSA key pair.
    """
    logger.info(f"Rotating RSA key pair with ID {existing_key_id}.")

    private_key, public_key = generate_rsa_key_pair(new_key_size)
    new_key_pair = serialize_key_pair(private_key, public_key, new_key_size)
    store_key_pair(new_key_pair, directory)

    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_INFO,
        category=LogCategory.LOG_CATEGORY_SECURITY,
        message=f"Rotated key pair for {existing_key_id}. New key ID: {new_key_pair.key_pair_id}.",
        sensitive=False
    )

    return new_key_pair
