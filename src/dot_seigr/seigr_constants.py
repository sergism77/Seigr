# src/dot_seigr/seigr_constants.py

import hashlib

# Target .seigr file size in bytes (adjusted after testing)
SEIGR_SIZE = 304 * 1024  # Results in ~539 KB after encoding and adjustments

# Encoding expansion factor (senary encoding overhead)
EXPANSION_FACTOR = 1.7  # Adjust as encoding efficiency improves

TRACE_CODE = "53194"  # Unique trace code for Seigr Urcelial-net

# Hashing and cryptographic settings
SALT_SIZE = 16  # Salt size in bytes
DEFAULT_ALGORITHM = "sha256"
SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# Tree depth configuration for hierarchical hashes
MAX_TREE_DEPTH = 6  # Maximum depth for multi-layered hash trees

# Calculate target binary segment size to match encoded SEIGR_SIZE target
TARGET_BINARY_SEGMENT_SIZE = int(SEIGR_SIZE / EXPANSION_FACTOR)

# Header and blank space configurations
HEADER_SIZE = 128
BLANK_SPACE_RATIO = 0.1  # 10% reserved for metadata and future expansion

# Cluster and replication parameters
CLUSTER_LIMIT = 20 * SEIGR_SIZE  # Max size for each cluster in bytes
MIN_REPLICATION = 6  # Minimum number of segment replications
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Max size of a seed cluster in bytes

# Version and unique identifier for tracking and compatibility
SEIGR_VERSION = "1.0"
SEIGR_TRACE_CODE = "53194"  # Unique identifier for `.seigr` files in Seigr Urcelial-net

# Adaptive replication demand thresholds
DEMAND_SCALE_THRESHOLD_LOW = 10     # Trigger low demand scale at 10 accesses
DEMAND_SCALE_THRESHOLD_MODERATE = 100  # Trigger moderate demand scale at 100 accesses
DEMAND_SCALE_THRESHOLD_HIGH = 1000  # Trigger high demand scale at 1000 accesses

# Path configurations for logs and backups
LOG_DIRECTORY = "logs"  # Directory for centralized logs
BACKUP_DIRECTORY = "backups"  # Directory for file backups

# Temporal and rollback settings for integrity management
TEMPORAL_LAYER_CHECK_INTERVAL = 86400  # Check daily for integrity in seconds
ROLLBACK_THRESHOLD = 3  # Number of failures before rollback triggers

# Resilience adjustments for production stability
MAX_RETRY_ATTEMPTS = 5  # Retry attempts for network operations
RETRY_BACKOFF_FACTOR = 2  # Exponential backoff factor for retries
TIMEOUT_SECONDS = 30  # Timeout for network operations in seconds
