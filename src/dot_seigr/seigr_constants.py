# src/dot_seigr/seigr_constants.py

# Target .seigr file size in bytes (after encoding)
SEIGR_SIZE = 304 * 1024

# Encoding expansion factor for senary encoding
EXPANSION_FACTOR = 1.7  # Adjust based on encoding overhead

# Calculate the binary segment size directly to fit the encoded SEIGR_SIZE target
TARGET_BINARY_SEGMENT_SIZE = int(SEIGR_SIZE / EXPANSION_FACTOR)

# Header and blank space adjustments (if needed)
HEADER_SIZE = 128
BLANK_SPACE_RATIO = 0.1  # Reserve 10% of each .seigr file for metadata and future updates

# Cluster and replication settings
CLUSTER_LIMIT = 20 * SEIGR_SIZE
MIN_REPLICATION = 6
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE
