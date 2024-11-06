# src/identity/seigr_identity.py
import os
import time
import json
import logging
from src.crypto.hypha_crypt import encode_to_senary, encrypt_data, decrypt_data, generate_encryption_key
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.hash_utils import hypha_hash

logger = logging.getLogger(__name__)

class SeigrIdentity:
    def __init__(self, user_entropy=None):
        """
        Initializes a SeigrIdentity instance with optional entropy for unique ID generation.

        Args:
            user_entropy (str, optional): Additional entropy for ID uniqueness. Default is None.
        """
        self.timestamp = int(time.time())
        self.user_entropy = user_entropy or os.urandom(16).hex()
        self.raw_id = None  # Raw ID before encoding
        self.senary_id = None  # Senary-encoded Seigr ID
        self.encryption_key = None  # Encryption key derived from password or private key

    def generate_seigr_id(self):
        """
        Generates a unique Seigr ID by hashing entropy and encoding it in senary format.

        Returns:
            str: Senary-encoded Seigr ID.
        """
        # Generate a raw hash based on timestamp and user entropy
        combined_data = f"{self.timestamp}{self.user_entropy}"
        self.raw_id = hypha_hash(combined_data)
        logger.debug(f"Generated raw ID (hex): {self.raw_id}")

        # Encode the hash to senary
        self.senary_id = encode_to_senary(bytes.fromhex(self.raw_id))
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
            self.encryption_key = hypha_hash(password)[:32]  # Derive encryption key from password
        elif private_key:
            self.encryption_key = private_key  # Use directly provided private key
        else:
            raise ValueError("A password or private key is required to set the encryption key.")
        
        logger.info("Encryption key set successfully.")

    def save_to_external(self, file_path):
        """
        Saves the Seigr ID securely to an external location (e.g., USB) using encryption.

        Args:
            file_path (str): Path to save the encrypted identity file.

        Raises:
            ValueError: If encryption key or senary ID is not set.
        """
        if not self.encryption_key or not self.senary_id:
            raise ValueError("Encryption key and Senary ID must be set before saving.")
        
        encrypted_id = encrypt_data(self.senary_id.encode(), self.encryption_key)
        identity_data = {
            "timestamp": self.timestamp,
            "senary_id": encrypted_id.decode('utf-8')  # Ensure JSON compatibility
        }
        
        with open(file_path, 'w') as f:
            json.dump(identity_data, f)
        
        logger.info(f"Seigr ID saved securely to {file_path}.")

    def load_from_external(self, file_path, password=None, private_key=None):
        """
        Loads and decrypts the Seigr ID from an external storage file.

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
            with open(file_path, 'r') as f:
                identity_data = json.load(f)
            
            encrypted_id = identity_data.get("senary_id").encode('utf-8')
            if not encrypted_id:
                logger.error("Failed to find encrypted ID in the file.")
                return False

            # Decrypt the ID using the encryption key
            decrypted_id = decrypt_data(encrypted_id, self.encryption_key).decode('utf-8')
            if decrypted_id:
                self.senary_id = decrypted_id
                logger.info("Seigr ID successfully loaded and decrypted.")
                return True
            else:
                logger.error("Failed to decrypt the Seigr ID.")
                return False
        except (FileNotFoundError, ValueError, IOError) as e:
            logger.error(f"Error loading Seigr ID from external file: {e}")
            return False

    def verify_identity(self, seigr_id):
        """
        Verifies a given Seigr ID by decoding and checking its format and length.

        Args:
            seigr_id (str): Seigr ID to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            decoded_id = int(seigr_id, 6)  # Decode from senary to validate format
            is_valid = len(seigr_id) == len(self.senary_id)  # Ensure length consistency
            logger.debug(f"ID verification result: {is_valid}")
            return is_valid
        except ValueError:
            logger.error("Invalid Seigr ID format for verification.")
            return False
