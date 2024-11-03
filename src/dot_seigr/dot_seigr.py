# src/dot_seigr/dot_seigr.py

from .compression import compress_data, encode_data
from .seigr_file import create_seigr, save_seigr
from .lineage import update_lineage, load_lineage
from .integrity import verify_integrity
from .replication import check_replication_count
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr  # Correctly import SeedDotSeigr

# Constants
SEIGR_SIZE = 539 * 1024  # Each .seigr file is 539 KB
HEADER_SIZE = 128        # Reserved space in bytes for the header
MIN_REPLICATION = 6      # Minimum replication threshold for each .seigr
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Seed cluster size limit in bytes


class DotSeigr:
    def __init__(self, data, creator_id, previous_hash=None, file_type="binary"):
        self.data = data
        self.creator_id = creator_id
        self.previous_hash = previous_hash or ""
        self.file_type = file_type
        self.version = "1.0"
        self.hash = ""
        self.replication_count = MIN_REPLICATION

    def create_and_save(self, directory: str, seed: SeedDotSeigr, part_index: int, total_parts: int):
        seigr_content = create_seigr(self.data, self.creator_id, self.previous_hash, part_index, total_parts)
        self.hash = seigr_content['header']['hash']
        seed = save_seigr(seigr_content, directory, seed)
        return seed
