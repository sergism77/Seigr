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

class SenaryEncoderDecoder:
    """Handles senary encoding and decoding for data compression and storage."""
    
    def encode_to_senary(self, binary_data: bytes) -> str:
        """Encodes binary data to a senary-encoded string."""
        senary_str = ""
        previous_value = 1
        for i, byte in enumerate(binary_data):
            transformed_byte = self.substitution_permutation(byte + previous_value, i)
            previous_value = transformed_byte
            senary_str += self.base6_encode(transformed_byte)
        logger.debug("Encoded data to senary format.")
        return senary_str

    def decode_from_senary(self, senary_str: str) -> bytes:
        """Decodes a senary (base-6) encoded string back to binary data."""
        binary_data = bytearray()
        previous_value = 1
        for i in range(0, len(senary_str), 2):
            byte = self.base6_decode(senary_str[i:i + 2])
            reversed_byte = self.reverse_substitution_permutation(byte, previous_value, i // 2)
            binary_data.append(reversed_byte)
            previous_value = byte
        logger.debug("Decoded senary data to binary format.")
        return bytes(binary_data)

    def substitution_permutation(self, value: int, position: int) -> int:
        substituted = (value ^ (position * 17 + 23)) & 0xFF
        rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
        return rotated

    def reverse_substitution_permutation(self, value: int, prev_val: int, position: int) -> int:
        rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
        substituted = (rotated ^ (position * 17 + 23)) & 0xFF
        return (substituted - prev_val) & 0xFF

    def base6_encode(self, byte: int) -> str:
        """Encodes a single byte to base-6 with 2-character padding."""
        senary = []
        while byte > 0:
            senary.append(str(byte % 6))
            byte //= 6
        return ''.join(reversed(senary)).zfill(2)

    def base6_decode(self, senary_str: str) -> int:
        """Decodes a base-6 encoded string to a single byte."""
        byte = 0
        for char in senary_str:
            byte = byte * 6 + int(char)
        return byte


class HyphaHasher:
    """Handles cryptographic hashing and dynamic salt generation."""

    def generate_primary_hash(self, data: str, salt: str = None, key: str = None) -> str:
        """Primary hash for individual .seigr files."""
        salt = salt or self.dynamic_salt()
        data_to_hash = salt + data + (key if key else "")
        logger.debug(f"Generating primary hash with salt={salt}")
        return hashlib.sha256(data_to_hash.encode()).hexdigest()

    def generate_secondary_hash(self, cluster_data: str, primary_hash: str, cluster_salt: str = None) -> str:
        """
        Secondary hash for seed clusters, linking multiple .seigr hashes.
        Args:
            cluster_data (str): Combined data of .seigr files within the cluster.
            primary_hash (str): Primary hash to link to.
            cluster_salt (str): Optional additional salt for the secondary hash.
        """
        cluster_salt = cluster_salt or self.dynamic_salt(seed=primary_hash[:8])
        data_to_hash = cluster_salt + cluster_data + primary_hash
        logger.debug(f"Generating secondary hash with cluster_salt={cluster_salt}")
        return hashlib.sha512(data_to_hash.encode()).hexdigest()  # SHA-512 for secondary hashing

    def dynamic_salt(self, seed: str = None) -> str:
        """Generates a dynamic salt with optional seed for hierarchical structure."""
        unique_id = uuid.uuid4()
        timestamp = int(time.time() * 1e6)
        entropy = int.from_bytes(urandom(2), 'little')
        salt = f"{unique_id.hex}{timestamp:016x}{entropy:04x}"
        if seed:
            salt += seed
        logger.debug(f"Generated dynamic salt: {salt}")
        return salt


class SecureRandomGenerator:
    """Generates secure random numbers using xorshift algorithm."""
    
    def secure_random(self, seed: int = None) -> int:
        if seed is None:
            seed = int.from_bytes(urandom(4), 'little')
        x = seed
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        logger.debug(f"Generated secure random number: {x}")
        return x & 0xFFFFFFFF
