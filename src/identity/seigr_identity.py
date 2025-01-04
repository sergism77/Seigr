# src/identity/seigr_identity.py

import logging

from src.crypto.hypha_crypt import encrypt_data
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeigrIdentityData
from src.identity.encryption_manager import EncryptionManager
from src.identity.generate_identity import IdentityGenerator
from src.identity.usb_manager import USBManager
from src.identity.verification_manager import VerificationManager

logger = logging.getLogger(__name__)


class SeigrIdentity:
    def __init__(self, user_entropy=None):
        self.generator = IdentityGenerator(user_entropy)
        self.encryption_manager = EncryptionManager()
        self.usb_manager = USBManager()
        self.senary_id = self.generator.generate_seigr_id()
        self.verification_manager = VerificationManager(self.senary_id)

    def set_encryption_and_keys(self, password=None, private_key=None):
        self.encryption_manager.set_encryption_and_keys(password, private_key)
        self.signature = self.encryption_manager.sign_identity(self.senary_id)

    def save_to_usb(self, usb_path):
        if not self.encryption_manager.encryption_key or not self.signature:
            raise ValueError("Encryption key and signature must be set before saving.")

        identity_data = SeigrIdentityData(
            timestamp=self.generator.timestamp,
            senary_id=encrypt_data(
                self.senary_id.encode(), self.encryption_manager.encryption_key
            ),
            owner_public_key=self.encryption_manager.public_key,
            encrypted_private_key=self.encryption_manager.encrypted_private_key,
            owner_signature=self.signature,
        )
        self.usb_manager.save_to_usb(identity_data, usb_path)

    def load_from_usb(self, usb_path, password=None):
        self.set_encryption_and_keys(password)
        file_name = f"{self.senary_id}.seigr"
        return self.usb_manager.load_from_usb(
            usb_path, file_name, self.encryption_manager.encryption_key
        )

    def verify_identity(self, seigr_id):
        return self.verification_manager.verify_identity_format(seigr_id)

    def sync_with_ipfs(self):
        return self.verification_manager.sync_with_ipfs()

    def check_usb_connection(self):
        return self.verification_manager.check_usb_connection()
