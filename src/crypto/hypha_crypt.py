# src/crypto/hypha_crypt.py
import logging
from os import urandom
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, cbor_encode_senary, cbor_decode_senary
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import OperationLog

# Set up centralized logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename='seigr_hypha_crypt.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

### Encryption Functions ###

def generate_encryption_key(password: str = None) -> bytes:
    """Generates a symmetric encryption key, optionally derived from a password."""
    if password:
        return hypha_hash(password)[:32]  # Derive key from password
    return Fernet.generate_key()  # Generate a random symmetric key

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password and a salt."""
    return hypha_hash(password + salt.hex())[:32]

def generate_salt() -> bytes:
    """Generates a cryptographic salt."""
    return urandom(16)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using the provided encryption key."""
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts data using the provided encryption key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

### Asymmetric Key Pair Functions ###

def generate_key_pair():
    """
    Generates a public/private key pair for signing and verification.
    
    Returns:
        tuple: A tuple containing the public key and private key in PEM format.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
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

    return public_key_pem, private_key_pem

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Signs data using a private RSA key.

    Args:
        data (bytes): Data to sign.
        private_key_pem (bytes): Private key in PEM format.

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
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verifies a digital signature using a public RSA key.

    Args:
        data (bytes): Original data that was signed.
        signature (bytes): Digital signature to verify.
        public_key_pem (bytes): Public key in PEM format.

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
        return True
    except InvalidSignature:
        return False

### Pseudo-Random Number Generation ###

def secure_random(seed: int = None) -> int:
    """Generates a secure random number using xorshift algorithm."""
    if seed is None:
        seed = int.from_bytes(urandom(4), 'little')
    x = seed
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5) & 0xFFFFFFFF
    logger.debug(f"Generated secure random number: {x}")
    return x & 0xFFFFFFFF

### Hierarchical Hash Tree and Logging ###

class HyphaCrypt:
    def __init__(self, data: bytes, segment_id: str, use_senary: bool = False):
        """
        Initializes HyphaCrypt for encryption, hashing, and traceability.
        
        Args:
            data (bytes): The data segment to be encoded and hashed.
            segment_id (str): Unique identifier for the segment (UUID or derived hash).
            use_senary (bool): Determines if senary encoding is applied to hash outputs.
        """
        self.data = data
        self.segment_id = segment_id
        self.primary_hash = None
        self.tree = {}  # Stores hash tree layers
        self.layer_logs = []  # Keeps all hash logs for traceability
        self.use_senary = use_senary

    def compute_primary_hash(self):
        """Computes and stores the primary hash of the data segment."""
        hash_input = self.data
        self.primary_hash = hypha_hash(hash_input, senary_output=self.use_senary)
        logger.info(f"Primary hash computed: {self.primary_hash} for segment {self.segment_id}")
        return self.primary_hash

    def compute_layered_hashes(self, layers=4):
        """Computes a hierarchical tree of hashes up to a specified depth."""
        if not self.primary_hash:
            self.compute_primary_hash()

        current_layer = [self.primary_hash]
        for depth in range(1, layers + 1):
            next_layer = []
            for item in current_layer:
                hash_input = f"{item}:{depth}".encode()
                layer_hash = hypha_hash(hash_input, algorithm="sha512", senary_output=self.use_senary)
                next_layer.append(layer_hash)
                self._log_layer_event(depth, layer_hash)

            self.tree[f"Layer_{depth}"] = next_layer
            current_layer = next_layer

        logger.info(f"Layered hashes computed up to depth {layers} for segment {self.segment_id}")
        return self.tree

    def _log_layer_event(self, depth, layer_hash):
        """Logs each layer's hash with metadata as OperationLog to the log list."""
        log_entry = OperationLog(
            operation_type="layer_hash",
            performed_by=self.segment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            details=f"Layer {depth} - Hash: {layer_hash}"
        )
        self.layer_logs.append(log_entry)
        logger.debug(f"Logged Layer {depth} - Hash: {layer_hash} for Segment {self.segment_id}")

    def export_log_tree(self, use_cbor: bool = False):
        """
        Exports the hash tree log to CBOR for efficient visualization and tracing.
        
        Args:
            use_cbor (bool): Exports as CBOR if True, otherwise uses protobuf binary format.
        
        Returns:
            str: Path to the saved log file.
        """
        filename = f"{self.segment_id}_tree_log.cbor"
        serialized_data = cbor_encode_senary([log_entry.SerializeToString() for log_entry in self.layer_logs])

        with open(filename, 'wb') as f:
            f.write(serialized_data)
        logger.info(f"Tree log exported to CBOR format in {filename} for segment {self.segment_id}")
        return filename

    def verify_integrity(self, reference_tree, partial_depth=None):
        """
        Verifies the integrity of the segment by comparing its hash tree with a reference tree.
        
        Args:
            reference_tree (dict): The hash tree structure to verify against.
            partial_depth (int): Depth of partial verification. Verifies full depth if None.
        
        Returns:
            bool: True if the hash trees match up to the specified depth, otherwise False.
        """
        current_tree = self.compute_layered_hashes(layers=partial_depth or 4)
        for depth in range(1, (partial_depth or 4) + 1):
            current_layer = current_tree.get(f"Layer_{depth}")
            reference_layer = reference_tree.get(f"Layer_{depth}")
            if current_layer != reference_layer:
                logger.warning(f"Integrity check failed at depth {depth} for segment {self.segment_id}")
                return False
        logger.info(f"Integrity verified up to depth {partial_depth or 4} for segment {self.segment_id}")
        return True
