# src/crypto/encoding_utils.py
import logging

logger = logging.getLogger(__name__)

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string."""
    senary_str = ""
    previous_value = 1  # Presumably used as an integer seed for transformations

    for i, byte in enumerate(binary_data):
        transformed_byte = _substitution_permutation(byte + previous_value, i)
        previous_value = transformed_byte
        base6_encoded = _base6_encode(transformed_byte)
        logger.debug(f"base6_encoded (should be str): {base6_encoded}, type: {type(base6_encoded)}")
        senary_str += base6_encoded  # _base6_encode should return a string

    logger.debug("Encoded data to senary format.")
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    binary_data = bytearray()
    previous_value = 1
    for i in range(0, len(senary_str), 2):
        byte = _base6_decode(senary_str[i:i + 2])
        reversed_byte = _reverse_substitution_permutation(byte, previous_value, i // 2)
        binary_data.append(reversed_byte)
        previous_value = byte
    logger.debug("Decoded senary data to binary format.")
    return bytes(binary_data)

# Helper functions
def _substitution_permutation(value: int, position: int) -> int:
    substituted = (value ^ (position * 17 + 23)) & 0xFF
    rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
    return rotated

def _reverse_substitution_permutation(value: int, prev_val: int, position: int) -> int:
    rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
    substituted = (rotated ^ (position * 17 + 23)) & 0xFF
    return (substituted - prev_val) & 0xFF

def _base6_encode(byte: int) -> str:
    senary = [str((byte // 6**i) % 6) for i in range((byte.bit_length() + 1) // 3 + 1)]
    return ''.join(reversed(senary)).zfill(2)

def _base6_decode(senary_str: str) -> int:
    byte = 0
    for char in senary_str:
        byte = byte * 6 + int(char)
    return byte
