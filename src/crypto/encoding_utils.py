# src/crypto/encoding_utils.py
import logging

logger = logging.getLogger(__name__)

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string with reversible transformations."""
    senary_str = ""
    previous_value = 1  # Used as a seed for reversible transformations

    for i, byte in enumerate(binary_data):
        transformed_byte = _substitution_permutation(byte + previous_value, i)
        previous_value = transformed_byte
        base6_encoded = _base6_encode(transformed_byte)
        senary_str += base6_encoded
        logger.debug(f"Encoded byte {i}: original {byte}, transformed {transformed_byte}, senary {base6_encoded}")

    logger.debug("Successfully encoded data to senary format.")
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    binary_data = bytearray()
    previous_value = 1

    # Each byte was encoded into 2-character senary pairs
    for i in range(0, len(senary_str), 2):
        encoded_pair = senary_str[i:i + 2]
        byte = _base6_decode(encoded_pair)
        reversed_byte = _reverse_substitution_permutation(byte, previous_value, i // 2)
        binary_data.append(reversed_byte)
        previous_value = byte
        logger.debug(f"Decoded pair {encoded_pair}: senary {byte}, original {reversed_byte}")

    logger.debug("Successfully decoded senary data back to binary format.")
    return bytes(binary_data)

# Helper functions for encoding and decoding transformations

def _substitution_permutation(value: int, position: int) -> int:
    """
    Applies a substitution and bit rotation to a byte, based on its position.
    """
    substituted = (value ^ (position * 17 + 23)) & 0xFF
    rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
    logger.debug(f"Substitution-permutation: input {value}, substituted {substituted}, rotated {rotated}")
    return rotated

def _reverse_substitution_permutation(value: int, prev_val: int, position: int) -> int:
    """
    Reverses the substitution and rotation applied in _substitution_permutation.
    """
    rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
    substituted = (rotated ^ (position * 17 + 23)) & 0xFF
    reversed_val = (substituted - prev_val) & 0xFF
    logger.debug(f"Reversed permutation: input {value}, rotated {rotated}, substituted {substituted}, result {reversed_val}")
    return reversed_val

def _base6_encode(byte: int) -> str:
    """
    Converts a single byte to a senary (base-6) encoded string.
    Returns a 2-character senary string, padding with leading zeros if necessary.
    """
    senary = [str((byte // 6**i) % 6) for i in range((byte.bit_length() + 1) // 3 + 1)]
    encoded = ''.join(reversed(senary)).zfill(2)
    logger.debug(f"Base-6 encoding: byte {byte}, senary {encoded}")
    return encoded

def _base6_decode(senary_str: str) -> int:
    """
    Converts a senary (base-6) encoded string back to a byte.
    """
    byte = 0
    for char in senary_str:
        byte = byte * 6 + int(char)
    logger.debug(f"Base-6 decoding: senary {senary_str}, byte {byte}")
    return byte

# CBOR-compatible wrapper functions
def cbor_encode_senary(data) -> bytes:
    """
    Wraps data in CBOR-compatible encoding, using senary encoding for binary fields.
    
    Args:
        data (dict or list): The data to encode. Supports dicts or lists of dicts.
    
    Returns:
        bytes: CBOR-encoded data with senary transformations.
    """
    import cbor2

    def encode_field(value):
        """Encodes individual fields to senary if they are bytes."""
        return encode_to_senary(value) if isinstance(value, bytes) else value

    # If `data` is a list, encode each dictionary entry; otherwise, assume it's a dictionary
    if isinstance(data, list):
        senary_data = [{key: encode_field(value) for key, value in item.items()} for item in data]
    elif isinstance(data, dict):
        senary_data = {key: encode_field(value) for key, value in data.items()}
    else:
        raise TypeError("cbor_encode_senary only supports dicts or lists of dicts.")

    cbor_encoded = cbor2.dumps(senary_data)
    logger.debug("Encoded data in CBOR with senary transformations.")
    return cbor_encoded

def cbor_decode_senary(cbor_data: bytes) -> dict:
    """
    Decodes CBOR data and decodes any senary-encoded fields back to binary.
    """
    import cbor2
    data = cbor2.loads(cbor_data)
    decoded_data = {key: decode_from_senary(value) if isinstance(value, str) and _is_senary(value) else value
                    for key, value in data.items()}
    logger.debug("Decoded CBOR data with senary transformations.")
    return decoded_data

def _is_senary(string: str) -> bool:
    """Checks if a string is a valid senary-encoded string."""
    return all(c in '012345' for c in string)
