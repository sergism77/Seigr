from src.crypto.constants import DEFAULT_HASH_FUNCTION, SUPPORTED_HASH_ALGORITHMS

# === Core Seigr Cell (`sc`) Specifications ===
SEIGR_CELL_UNIT = 1  # 1 Seigr Cell (sc) as the fundamental data unit in Seigr
SC_TRACE_CODE = "sc_001"  # Unique identifier for tracking Seigr Cell lineage
SEIGR_VERSION = "1.0"  # Protocol version for compatibility tracking

# === Cryptographic & Hashing Settings ===
SALT_SIZE = 16  # Salt size in bytes for hashing
MAX_TREE_DEPTH = 6  # Max depth for multi-dimensional hash trees in `.seigr` segments
DEFAULT_SENARY_HASH_LAYER = 3  # Default layer depth for senary path encoding

# === File Structure & Metadata Configuration (in terms of `sc`) ===
HEADER_SC_UNITS = 2  # Seigr Cells reserved for file headers
BLANK_SPACE_RATIO = 0.1  # Reserved metadata space, 10% of each segment
TARGET_SC_SEGMENT_SIZE = SEIGR_CELL_UNIT * 0.6  # Optimal sc size for encoded segments
TEMPORAL_LAYER_METADATA_SIZE = 4  # Metadata size in sc for temporal layers

# === Cluster & Replication Settings (in `sc` units) ===
MIN_REPLICATION = 6  # Minimum replication per segment for redundancy
CLUSTER_LIMIT_SC = 20 * SEIGR_CELL_UNIT  # Max cluster size in sc
MAX_SEED_CLUSTER_SC_SIZE = CLUSTER_LIMIT_SC  # Limit for primary seed clusters in `sc`
PRIMARY_LINK_REPLICATION_THRESHOLD = 3  # Threshold before primary links require more replication

# === Adaptive Demand Scaling ===
DEMAND_SCALE_THRESHOLD_SC = {
    "low": 1 * SEIGR_CELL_UNIT,       # Low demand scaling threshold in `sc`
    "moderate": 10 * SEIGR_CELL_UNIT, # Moderate demand scaling threshold in `sc`
    "high": 100 * SEIGR_CELL_UNIT     # High demand scaling threshold in `sc`
}
SCALE_BACK_TRIGGER = 5  # Trigger scale-back if demand falls below threshold

# === Access Control & Logging ===
LOG_DIRECTORY = "logs"  # Directory for logs
BACKUP_DIRECTORY = "backups"  # Directory for file backups
DEFAULT_ACL_ROLES = {
    "admin": {"read": True, "write": True, "rollback": True},
    "user": {"read": True, "write": False, "rollback": False},
}
DEFAULT_ACL_ROLE = "user"  # Default role assignment for new users

# === Integrity & Temporal Layer Management ===
TEMPORAL_LAYER_CHECK_INTERVAL = 86400  # Interval (in seconds) for integrity checks (daily)
ROLLBACK_THRESHOLD = 3  # Trigger rollback after 3 failed integrity checks
TEMPORAL_LAYER_SNAPSHOT_FREQUENCY = 7  # Number of access events before creating a snapshot

# === Resilience & Network Stability ===
MAX_RETRY_ATTEMPTS = 5  # Max retry attempts for network operations
RETRY_BACKOFF_FACTOR = 2  # Backoff multiplier for retries
TIMEOUT_SECONDS = 30  # Timeout (in seconds) for network operations

# === Additional Parameters for Protobuf Integration ===
PROTOCOL_ENCODING = "protobuf"  # Encoding type for Seigr Cells
SERIALIZATION_FORMAT = "cbor"  # Alternative serialization format

# === Miscellaneous Settings ===
TEMPORARY_STORAGE_DIR = "temp_storage"  # Directory for temporary storage
