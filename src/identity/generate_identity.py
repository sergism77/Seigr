# src/identity/generate_identity.py

import logging
import os
import time

from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hypha_crypt import encode_to_senary

logger = logging.getLogger(__name__)


class IdentityGenerator:
    SEIGR_PREFIX = encode_to_senary(b"seigr")

    def __init__(self, user_entropy=None):
        self.timestamp = int(time.time())
        self.user_entropy = user_entropy or os.urandom(16).hex()

    def generate_seigr_id(self):
        combined_data = f"{self.timestamp}{self.user_entropy}".encode()
        hypha_crypt = HyphaCrypt(combined_data, segment_id="identity")
        raw_id = hypha_crypt.hypha_hash_wrapper(combined_data)
        senary_id = self.SEIGR_PREFIX + encode_to_senary(raw_id)
        logger.info(f"Generated Seigr ID: {senary_id}")
        return senary_id
