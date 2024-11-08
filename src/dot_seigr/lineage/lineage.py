import logging
from .lineage_entry import LineageEntry
from .lineage_serializer import LineageSerializer
from .lineage_storage import LineageStorage
from .lineage_integrity import LineageIntegrity

logger = logging.getLogger(__name__)

class Lineage:
    def __init__(self, creator_id: str, initial_hash: str = None):
        self.creator_id = creator_id
        self.entries = []
        self.version = "1.0"
        self.current_hash = initial_hash
        self.integrity_checker = LineageIntegrity()

    def add_entry(self, action: str, contributor_id: str, previous_hashes=None, metadata=None):
        entry = LineageEntry(
            version=self.version,
            action=action,
            creator_id=self.creator_id,
            contributor_id=contributor_id,
            previous_hashes=previous_hashes or [self.current_hash],
            metadata=metadata
        )
        self.current_hash = entry.calculate_hash()
        self.entries.append(entry.to_dict())
        logger.info(f"Added lineage entry. Updated hash: {self.current_hash}")

    def save_to_disk(self, storage_path: str):
        LineageStorage.save_to_disk(self, storage_path)

    def load_from_disk(self, storage_path: str):
        loaded_lineage = LineageStorage.load_from_disk(storage_path)
        self.creator_id = loaded_lineage["creator_id"]
        self.current_hash = loaded_lineage["current_hash"]
        self.version = loaded_lineage["version"]
        self.entries = loaded_lineage["entries"]

    def verify_integrity(self, reference_hash: str) -> bool:
        return self.integrity_checker.verify(self.current_hash, reference_hash)

    def ping_activity(self):
        self.last_ping = self.integrity_checker.ping_activity()
