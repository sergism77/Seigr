import json
from typing import Any, Dict
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_cell.utils.validation_utils import validate_metadata_schema
import logging

# Initialize Logger
logger = logging.getLogger(__name__)


### 🗃️ Serialization and Deserialization ###

def serialize_metadata(metadata: Dict[str, Any]) -> bytes:
    """
    Serializes metadata into a JSON-encoded binary format.
    
    Args:
        metadata (dict): Metadata dictionary to serialize.

    Returns:
        bytes: JSON-encoded binary data.
    
    Raises:
        ValueError: If serialization or validation fails.
    """
    try:
        validate_metadata_schema(metadata)
        json_data = json.dumps(metadata)
        serialized_data = json_data.encode('utf-8')
        logger.info("Metadata serialized successfully.")
        return serialized_data
    except Exception as e:
        logger.error(f"Failed to serialize metadata: {e}")
        raise ValueError("Serialization failed.") from e


def deserialize_metadata(serialized_data: bytes) -> Dict[str, Any]:
    """
    Deserializes binary metadata back into a Python dictionary.
    
    Args:
        serialized_data (bytes): JSON-encoded binary data.

    Returns:
        dict: Deserialized metadata dictionary.
    
    Raises:
        ValueError: If deserialization or validation fails.
    """
    try:
        json_data = serialized_data.decode('utf-8')
        metadata = json.loads(json_data)
        validate_metadata_schema(metadata)
        logger.info("Metadata deserialized successfully.")
        return metadata
    except Exception as e:
        logger.error(f"Failed to deserialize metadata: {e}")
        raise ValueError("Deserialization failed.") from e


### 🔒 Encryption and Decryption with HyphaCrypt ###

def encode_with_password(data: bytes, password: str, segment_id: str = "default_segment") -> bytes:
    """
    Encrypts data with a password using HyphaCrypt.

    Args:
        data (bytes): Data to encrypt.
        password (str): Password for encryption.
        segment_id (str): Identifier for encryption context.

    Returns:
        bytes: Encrypted data.
    
    Raises:
        ValueError: If encryption fails.
    """
    try:
        hypha_crypt = HyphaCrypt(data=data, segment_id=segment_id)
        encryption_key = hypha_crypt.generate_encryption_key(password)
        encrypted_data = hypha_crypt.encrypt_data(encryption_key)
        logger.info("Data encrypted successfully using HyphaCrypt.")
        return encrypted_data
    except Exception as e:
        logger.error(f"Failed to encrypt data using HyphaCrypt: {e}")
        raise ValueError("Encryption failed.") from e


def decode_with_password(encoded_data: bytes, password: str, segment_id: str = "default_segment") -> bytes:
    """
    Decrypts data with a password using HyphaCrypt.

    Args:
        encoded_data (bytes): Encrypted data.
        password (str): Password for decryption.
        segment_id (str): Identifier for encryption context.

    Returns:
        bytes: Decrypted data.
    
    Raises:
        ValueError: If decryption fails.
    """
    try:
        hypha_crypt = HyphaCrypt(data=b"", segment_id=segment_id)  # Placeholder data for context
        decryption_key = hypha_crypt.generate_encryption_key(password)
        decrypted_data = hypha_crypt.decrypt_data(encoded_data, decryption_key)
        logger.info("Data decrypted successfully using HyphaCrypt.")
        return decrypted_data
    except Exception as e:
        logger.error(f"Failed to decrypt data using HyphaCrypt: {e}")
        raise ValueError("Decryption failed.") from e
