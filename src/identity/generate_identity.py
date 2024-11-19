# src/identity/generate_identity.py

import os
import time
from src.crypto.hash_utils import hypha_hash
from src.crypto.hypha_crypt import encode_to_senary
import logging

logger = logging.getLogger(__name__)


class IdentityGenerator:
    SEIGR_PREFIX = encode_to_senary(b"seigr")

    def __init__(self, user_entropy=None):
        self.timestamp = int(time.time())
        self.user_entropy = user_entropy or os.urandom(16).hex()

    def generate_seigr_id(self):
        combined_data = f"{self.timestamp}{self.user_entropy}".encode()
        raw_id = hypha_hash(combined_data)
        senary_id = self.SEIGR_PREFIX + encode_to_senary(raw_id)
        logger.info(f"Generated Seigr ID: {senary_id}")
        return senary_id
