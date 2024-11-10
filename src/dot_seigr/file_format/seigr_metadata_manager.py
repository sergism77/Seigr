from datetime import datetime, timezone
from src.dot_seigr.seigr_constants import SEIGR_VERSION

class MetadataManager:
    def __init__(self, creator_id, index, file_type):
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.metadata = None

    def generate_metadata(self, hypha_crypt):
        self.metadata = {
            "version": SEIGR_VERSION,
            "creator_id": self.creator_id,
            "index": self.index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "segment_hash": hypha_crypt.compute_primary_hash()
        }
        return self.metadata

    def get_metadata(self):
        return self.metadata
