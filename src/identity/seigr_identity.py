# src/identity/seigr_identity.py
import os
import time
import logging
from src.crypto.hypha_crypt import encode_to_senary, encrypt_data, decrypt_data, generate_encryption_key
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeigrIdentityData

logger = logging.getLogger(__name__)

class SeigrIdentity:
    SEIGR_PREFIX = encode_to_senary(b"seigr")  # Prefix for all Seigr IDs in senary

    def __init__(self, user_entropy=None):
        """
        Initializes a SeigrIdentity instance with optional entropy for unique ID generation.

        Args:
            user_entropy (str, optional): Additional entropy for ID uniqueness. Default is None.
        """
        self.timestamp = int(time.time())
        self.user_entropy = user_entropy or os.urandom(16).hex()
        self.raw_id = None
        self.senary_id = None
        self.encryption_key = None

    def generate_seigr_id(self):
        """
        Generates a unique Seigr ID with the "seigr" prefix and senary encoding.

        Returns:
            str: Senary-encoded Seigr ID with prefix.
        """
        combined_data = f"{self.timestamp}{self.user_entropy}"
        self.raw_id = hypha_hash(combined_data)
        logger.debug(f"Generated raw ID (hex): {self.raw_id}")

        self.senary_id = self.SEIGR_PREFIX + encode_to_senary(bytes.fromhex(self.raw_id))
        logger.info(f"Generated Seigr ID (senary): {self.senary_id}")
        return self.senary_id

    def set_encryption_key(self, password=None, private_key=None):
        """
        Sets the encryption key based on a password or a provided private key.

        Args:
            password (str): User-provided password for key derivation.
            private_key (str): Optional custom private key.

        Raises:
            ValueError: If neither password nor private_key is provided.
        """
        if password:
            self.encryption_key = hypha_hash(password)[:32]
        elif private_key:
            self.encryption_key = private_key
        else:
            raise ValueError("A password or private key is required to set the encryption key.")
        
        logger.info("Encryption key set successfully.")

    def save_to_external(self, file_path):
        """
        Saves the Seigr ID securely to an external location using encryption and protocol buffers.

        Args:
            file_path (str): Path to save the encrypted identity file.

        Raises:
            ValueError: If encryption key or senary ID is not set.
        """
        if not self.encryption_key or not self.senary_id:
            raise ValueError("Encryption key and Senary ID must be set before saving.")
        
        encrypted_id = encrypt_data(self.senary_id.encode(), self.encryption_key)

        # Create and serialize a SeigrIdentityData protobuf message
        identity_data = SeigrIdentityData(
            timestamp=self.timestamp,
            senary_id=encrypted_id
        )
        
        with open(file_path, 'wb') as f:
            f.write(identity_data.SerializeToString())
        
        logger.info(f"Seigr ID saved securely to {file_path}.")

    def load_from_external(self, file_path, password=None, private_key=None):
        """
        Loads and decrypts the Seigr ID from an external storage file using protocol buffers.

        Args:
            file_path (str): Path to the encrypted identity file.
            password (str): Password for decrypting the identity.
            private_key (str): Optional private key for decryption.

        Returns:
            bool: True if identity is successfully loaded and decrypted, False otherwise.
        """
        if password:
            self.set_encryption_key(password=password)
        elif private_key:
            self.set_encryption_key(private_key=private_key)
        else:
            raise ValueError("A password or private key is required to load the identity.")
        
        try:
            with open(file_path, 'rb') as f:
                identity_data = SeigrIdentityData()
                identity_data.ParseFromString(f.read())
            
            encrypted_id = identity_data.senary_id
            decrypted_id = decrypt_data(encrypted_id, self.encryption_key).decode('utf-8')
            if decrypted_id.startswith(self.SEIGR_PREFIX):
                self.senary_id = decrypted_id
                logger.info("Seigr ID successfully loaded and decrypted.")
                return True
            else:
                logger.error("Decrypted ID does not have a valid Seigr prefix.")
                return False
        except (FileNotFoundError, ValueError, IOError) as e:
            logger.error(f"Error loading Seigr ID from external file: {e}")
            return False

    def verify_identity(self, seigr_id):
        """
        Verifies a given Seigr ID by checking for the correct prefix and format.

        Args:
            seigr_id (str): Seigr ID to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        is_valid = seigr_id.startswith(self.SEIGR_PREFIX) and len(seigr_id) == len(self.senary_id)
        logger.debug(f"ID verification result: {is_valid}")
        return is_valid
