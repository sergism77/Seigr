# src/identity/encryption_manager.py

import logging

from src.crypto.hypha_crypt import (
    encrypt_data,
    generate_encryption_key,
    generate_key_pair,
    sign_data,
    verify_signature,
)

logger = logging.getLogger(__name__)


class EncryptionManager:
    def __init__(self):
        self.encryption_key = None
        self.public_key = None
        self.private_key = None
        self.signature = None

    def set_encryption_and_keys(self, password=None, private_key=None):
        if password:
            self.encryption_key = generate_encryption_key(password)
        elif private_key:
            self.encryption_key = private_key
        else:
            raise ValueError("A password or private key is required.")

        if not private_key:
            self.public_key, self.private_key = generate_key_pair()
        else:
            self.private_key = private_key

        self.encrypted_private_key = encrypt_data(self.private_key, self.encryption_key)
        logger.info("Encryption and key generation complete.")

    def sign_identity(self, senary_id):
        self.signature = sign_data(senary_id.encode(), self.private_key)
        return self.signature

    def verify_signature(self, data, signature, public_key):
        return verify_signature(data.encode(), signature, public_key)
