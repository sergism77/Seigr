# src/dot_seigr/seigr_constants.py

# SEIGR_SIZE fine-tuning to reach 539 KB target size after encoding
SEIGR_SIZE = 272 * 1024 

# Encoding expansion factor for senary encoding
EXPANSION_FACTOR = 1.7

# Calculate binary segment size based on target SEIGR_SIZE and expansion factor
TARGET_BINARY_SEGMENT_SIZE = int(SEIGR_SIZE / EXPANSION_FACTOR)

# Header and blank space adjustments
HEADER_SIZE = 128
BLANK_SPACE_RATIO = 0.1  # Reserve 10% of each .seigr file for metadata

# Cluster settings
CLUSTER_LIMIT = 20 * SEIGR_SIZE  # Max size for each seed cluster in bytes
MIN_REPLICATION = 6  # Minimum replication threshold for each .seigr file

# Limits for Seigr file and cluster handling
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Max cluster size for seed files in bytes
