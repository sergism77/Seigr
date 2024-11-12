# src/crypto/cbor_utils.py

import logging
import cbor2
from typing import Any, Union
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary

# Initialize logger
logger = logging.getLogger(__name__)

def encode_data(data: Any, use_senary: bool = False) -> bytes:
    """
    Encodes data into CBOR format, with optional senary encoding for binary fields.
    
    Args:
        data (Any): Data to encode, expected to be a dictionary or list containing primitives.
        use_senary (bool): If True, encodes binary data to senary strings before CBOR encoding.

    Returns:
        bytes: CBOR-encoded data.
    """
    def transform_data(value):
        """Encodes binary fields to senary if enabled."""
        if isinstance(value, bytes) and use_senary:
            return encode_to_senary(value)
        elif isinstance(value, dict):
            return {k: transform_data(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [transform_data(v) for v in value]
        return value

    transformed_data = transform_data(data)
    encoded = cbor2.dumps(transformed_data)
    logger.debug("Data encoded to CBOR format with senary encoding applied: %s", use_senary)
    return encoded

def decode_data(cbor_data: bytes, use_senary: bool = False) -> Union[dict, list]:
    """
    Decodes CBOR data, converting any senary-encoded strings back to binary if enabled.
    
    Args:
        cbor_data (bytes): The CBOR-encoded data.
        use_senary (bool): If True, decodes senary-encoded strings back to binary.

    Returns:
        Union[dict, list]: The decoded data with senary strings converted back to binary if applicable.
    """
    def transform_data(value):
        """Decodes senary fields back to binary if enabled."""
        if isinstance(value, str) and use_senary and _is_senary(value):
            return decode_from_senary(value)
        elif isinstance(value, dict):
            return {k: transform_data(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [transform_data(v) for v in value]
        return value

    decoded = cbor2.loads(cbor_data)
    transformed_data = transform_data(decoded)
    logger.debug("Data decoded from CBOR format with senary decoding applied: %s", use_senary)
    return transformed_data

def _is_senary(string: str) -> bool:
    """Checks if a string is a valid senary-encoded string."""
    return all(c in '012345' for c in string)

def save_to_file(data: Any, file_path: str, use_senary: bool = False) -> None:
    """
    Encodes data to CBOR and saves it to a file.

    Args:
        data (Any): The data to be encoded and saved.
        file_path (str): The file path where the encoded data should be saved.
        use_senary (bool): If True, senary-encodes binary fields in the data.
    """
    encoded_data = encode_data(data, use_senary=use_senary)
    with open(file_path, 'wb') as file:
        file.write(encoded_data)
    logger.info(f"CBOR data saved to file: {file_path}")

def load_from_file(file_path: str, use_senary: bool = False) -> Union[dict, list]:
    """
    Loads CBOR-encoded data from a file and decodes it.

    Args:
        file_path (str): The path to the CBOR-encoded file.
        use_senary (bool): If True, decodes senary-encoded strings back to binary.

    Returns:
        Union[dict, list]: The decoded data.
    """
    with open(file_path, 'rb') as file:
        cbor_data = file.read()
    decoded_data = decode_data(cbor_data, use_senary=use_senary)
    logger.info(f"CBOR data loaded from file: {file_path}")
    return decoded_data
