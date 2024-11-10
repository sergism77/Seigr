# src/identity/usb_manager.py

import os
from src.crypto.hypha_crypt import encrypt_data, decrypt_data
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeigrIdentityData
import logging

logger = logging.getLogger(__name__)

class USBManager:
    USB_DIRECTORY_NAME = "Seigr"

    def save_to_usb(self, identity_data, usb_path):
        seigr_path = os.path.join(usb_path, self.USB_DIRECTORY_NAME)
        os.makedirs(seigr_path, exist_ok=True)
        file_path = os.path.join(seigr_path, f"{identity_data.senary_id}.seigr")

        with open(file_path, 'wb') as f:
            f.write(identity_data.SerializeToString())
        logger.info(f"Identity saved to {file_path}")

    def load_from_usb(self, usb_path, file_name, encryption_key):
        file_path = os.path.join(usb_path, self.USB_DIRECTORY_NAME, file_name)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"No file found at {file_path}")

        with open(file_path, 'rb') as f:
            identity_data = SeigrIdentityData()
            identity_data.ParseFromString(f.read())

        decrypted_id = decrypt_data(identity_data.senary_id, encryption_key).decode('utf-8')
        decrypted_private_key = decrypt_data(identity_data.encrypted_private_key, encryption_key)
        return decrypted_id, decrypted_private_key, identity_data
