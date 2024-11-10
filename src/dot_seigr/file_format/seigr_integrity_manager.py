from src.crypto.hash_utils import hypha_hash

class IntegrityManager:
    def __init__(self, data, hypha_crypt):
        self.data = data
        self.hypha_crypt = hypha_crypt
        self.checksum = None

    def compute_integrity(self, metadata):
        integrity_data = f"{metadata['segment_hash']}{hypha_hash(self.data)}".encode('utf-8')
        self.checksum = hypha_hash(integrity_data)
