# src/dot_seigr/seigr_constants.py

import hashlib

# === Core `.seigr` File Specifications ===
SEIGR_SIZE = 54333440  # bytes, exact target size for 53194 KB
EXPANSION_FACTOR = 1.7  # Estimated overhead for senary encoding
TRACE_CODE = "53194"  # Unique trace identifier for Seigr Urcelial-net and `.seigr` lineage

# === Cryptographic & Hashing Settings ===
SALT_SIZE = 16  # Salt size in bytes for hash randomization
DEFAULT_ALGORITHM = "sha256"  # Default hash algorithm for consistency
SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}
MAX_TREE_DEPTH = 6  # Maximum depth for multi-dimensional hash trees in `.seigr` segments

# === File Structure & Metadata Configuration ===
HEADER_SIZE = 128  # Bytes reserved for file headers, including versioning and IDs
BLANK_SPACE_RATIO = 0.1  # Reserved metadata space, 10% of each segment for future expansion
TARGET_BINARY_SEGMENT_SIZE = int(SEIGR_SIZE / EXPANSION_FACTOR)  # Optimal size for binary segment pre-encoding

# === Cluster & Replication Settings ===
MIN_REPLICATION = 6  # Minimum replication per segment for redundancy
CLUSTER_LIMIT = 20 * SEIGR_SIZE  # Max size per cluster in bytes before segmentation
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Max size for a primary seed cluster

# === Adaptive Demand Scaling ===
DEMAND_SCALE_THRESHOLD_LOW = 10     # Low demand scaling triggered at 10 accesses
DEMAND_SCALE_THRESHOLD_MODERATE = 100  # Moderate demand scaling triggered at 100 accesses
DEMAND_SCALE_THRESHOLD_HIGH = 1000  # High demand scaling triggered at 1000 accesses

# === Version & Tracking ===
SEIGR_VERSION = "1.0"  # Protocol version for compatibility tracking
SEIGR_TRACE_CODE = TRACE_CODE  # Unique identifier for Seigr Urcelial-net segments

# === Path Configurations for Logs & Backups ===
LOG_DIRECTORY = "logs"  # Directory for centralized logs
BACKUP_DIRECTORY = "backups"  # Directory for maintaining file backups

# === Integrity & Temporal Layer Management ===
TEMPORAL_LAYER_CHECK_INTERVAL = 86400  # Daily interval (in seconds) for integrity checks on segments
ROLLBACK_THRESHOLD = 3  # Trigger rollback after 3 failed integrity checks

# === Resilience & Network Stability ===
MAX_RETRY_ATTEMPTS = 5  # Max retry attempts for network operations
RETRY_BACKOFF_FACTOR = 2  # Exponential backoff multiplier for retries
TIMEOUT_SECONDS = 30  # Timeout setting (in seconds) for network-related operations

# === Additional Parameters for Protobuf Integration ===
# Placeholder for any potential additions to Protobuf configurations as they evolve
PROTOCOL_ENCODING = "protobuf"  # Protocol encoding type for `.seigr` files

