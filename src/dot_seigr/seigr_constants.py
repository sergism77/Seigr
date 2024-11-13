from src.crypto.hypha_crypt import HyphaCrypt

# === Core `.seigr` File Specifications ===
SEIGR_SIZE = 53194  # Target size in bytes for `.seigr` files
EXPANSION_FACTOR = 1.7  # Estimated overhead for senary encoding
TRACE_CODE = "53194"  # Unique trace identifier for Seigr Urcelial-net and `.seigr` lineage
SEIGR_VERSION = "1.0"  # Protocol version for compatibility tracking

# === Cryptographic & Hashing Settings using HyphaCrypt ===
SALT_SIZE = 16  # Salt size in bytes for hash randomization
DEFAULT_HASH_FUNCTION = HyphaCrypt.hash  # HyphaCrypt's primary hash function for default usage
SUPPORTED_HASH_ALGORITHMS = {
    "hypha_hash": HyphaCrypt.hash,
    "hypha_senary": HyphaCrypt.senary_hash,
}
MAX_TREE_DEPTH = 6  # Max depth for multi-dimensional hash trees in `.seigr` segments
DEFAULT_SENARY_HASH_LAYER = 3  # Default layer depth for senary path encoding

# === File Structure & Metadata Configuration ===
HEADER_SIZE = 128  # Bytes reserved for file headers
BLANK_SPACE_RATIO = 0.1  # Reserved metadata space, 10% of each segment for future expansion
TARGET_BINARY_SEGMENT_SIZE = int(SEIGR_SIZE / EXPANSION_FACTOR)  # Optimal pre-encoding segment size
TEMPORAL_LAYER_METADATA_SIZE = 256  # Bytes reserved for temporal layer metadata

# === Cluster & Replication Settings ===
MIN_REPLICATION = 6  # Minimum replication per segment for redundancy
CLUSTER_LIMIT = 20 * SEIGR_SIZE  # Max size per cluster in bytes
MAX_SEED_CLUSTER_SIZE = CLUSTER_LIMIT  # Limit for primary seed clusters
PRIMARY_LINK_REPLICATION_THRESHOLD = 3  # Min count before primary links need extra replication

# === Adaptive Demand Scaling ===
DEMAND_SCALE_THRESHOLD = {
    "low": 10,       # Low demand scaling threshold
    "moderate": 100, # Moderate demand scaling threshold
    "high": 1000     # High demand scaling threshold
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
PROTOCOL_ENCODING = "protobuf"  # Encoding type for `.seigr` files
SERIALIZATION_FORMAT = "cbor"  # Alternative serialization format

# === Miscellaneous Settings ===
TEMPORARY_STORAGE_DIR = "temp_storage"  # Directory for temporary storage
