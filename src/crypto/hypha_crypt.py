import time
import hashlib
import uuid
import logging
from os import urandom

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Constants
SALT_SIZE = 16  # Salt size in bytes
SEG_SIZE = 539 * 1024  # Reference size of each .seigr file

### Senary Encoding and Decoding Functions ###

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string."""
    senary_str = ""
    previous_value = 1
    for i, byte in enumerate(binary_data):
        transformed_byte = _substitution_permutation(byte + previous_value, i)
        previous_value = transformed_byte
        senary_str += _base6_encode(transformed_byte)
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

# Private helper functions for encoding and decoding

def _substitution_permutation(value: int, position: int) -> int:
    substituted = (value ^ (position * 17 + 23)) & 0xFF
    rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
    return rotated

def _reverse_substitution_permutation(value: int, prev_val: int, position: int) -> int:
    rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
    substituted = (rotated ^ (position * 17 + 23)) & 0xFF
    return (substituted - prev_val) & 0xFF

def _base6_encode(byte: int) -> str:
    """Encodes a single byte to base-6 with 2-character padding."""
    senary = []
    while byte > 0:
        senary.append(str(byte % 6))
        byte //= 6
    return ''.join(reversed(senary)).zfill(2)

def _base6_decode(senary_str: str) -> int:
    """Decodes a base-6 encoded string to a single byte."""
    byte = 0
    for char in senary_str:
        byte = byte * 6 + int(char)
    return byte

### Hashing and Salt Generation Functions ###

def generate_hash(data: str, salt: str = None, key: str = None, hash_type="primary") -> str:
    """Generates a hash with optional key and salt, for primary or secondary purposes."""
    salt = salt or dynamic_salt()
    data_to_hash = salt + data + (key if key else "")
    
    if hash_type == "primary":
        logger.debug(f"Generating primary SHA-256 hash with salt={salt}")
        return hashlib.sha256(data_to_hash.encode()).hexdigest()
    elif hash_type == "secondary":
        logger.debug(f"Generating secondary SHA-512 hash with salt={salt}")
        return hashlib.sha512(data_to_hash.encode()).hexdigest()
    else:
        raise ValueError("Invalid hash_type specified. Use 'primary' or 'secondary'.")

def dynamic_salt(seed: str = None) -> str:
    """Generates a dynamic salt, optionally seeded."""
    unique_id = uuid.uuid4()
    timestamp = int(time.time() * 1e6)
    entropy = int.from_bytes(urandom(2), 'little')
    salt = f"{unique_id.hex}{timestamp:016x}{entropy:04x}"
    if seed:
        salt += seed
    logger.debug(f"Generated dynamic salt: {salt}")
    return salt

### Pseudo-Random Number Generation ###

def secure_random(seed: int = None) -> int:
    """Generates a secure random number using the xorshift algorithm."""
    if seed is None:
        seed = int.from_bytes(urandom(4), 'little')
    x = seed
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5) & 0xFFFFFFFF
    logger.debug(f"Generated secure random number: {x}")
    return x & 0xFFFFFFFF
