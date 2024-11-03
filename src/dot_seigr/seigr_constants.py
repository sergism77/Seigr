# src/dot_seigr/seigr_constants.py

# Each .seigr file size limit
SEIGR_SIZE = 539 * 1024  # .seigr file size in bytes (539 KB)
HEADER_SIZE = 128        # Reserved header space in bytes for each .seigr file

# Cluster settings
CLUSTER_LIMIT = 20 * SEIGR_SIZE  # Maximum size for each seed cluster in bytes

# Encoding settings
BLANK_SPACE_RATIO = 0.1  # Reserve 10% of each .seigr file for future updates
MIN_REPLICATION = 6      # Minimum replication threshold for each .seigr file

# Limits for Seigr file and cluster handling
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Max cluster size for seed files in bytes
