# src/identity/verification_manager.py

import logging
import os

from src.identity.usb_manager import USBManager
from src.ipfs.ipfs_manager import IPFSManager

logger = logging.getLogger(__name__)


class VerificationManager:
    def __init__(self, senary_id):
        self.senary_id = senary_id
        self.ipfs_manager = IPFSManager(seigr_id=senary_id)

    def verify_identity_format(self, seigr_id):
        return seigr_id.startswith(self.senary_id[:6]) and len(seigr_id) == len(self.senary_id)

    def sync_with_ipfs(self):
        try:
            synced_files = self.ipfs_manager.sync_files(self.senary_id)
            logger.info(f"IPFS sync complete. Files: {synced_files}")
            return True
        except Exception as e:
            logger.error(f"IPFS sync failed: {e}")
            return False

    def check_usb_connection(self):
        possible_paths = ["/media", "/mnt", "/Volumes"]
        for path in possible_paths:
            usb_path = os.path.join(path, USBManager.USB_DIRECTORY_NAME)
            if os.path.exists(usb_path):
                logger.info(f"USB connected at {usb_path}")
                return usb_path
        logger.warning("Seigr USB not connected.")
        return None
