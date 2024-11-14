# src/crypto/constants.py

from src.crypto.hypha_crypt import HyphaCrypt

# === Core Seigr Protocol Identifiers ===
SEIGR_CELL_ID_PREFIX = "SEIGR"  # Prefix for identifiers related to Seigr protocol entities
SEIGR_VERSION = "1.0"  # Current version of Seigr protocol for compatibility tracking

# === Cryptographic & Hashing Settings with Seigr Cell Context ===
DEFAULT_HASH_FUNCTION = HyphaCrypt.hash  # Use HyphaCrypt's primary hash
SUPPORTED_HASH_ALGORITHMS = {
    "hypha_hash": HyphaCrypt.hash,
    "hypha_senary": HyphaCrypt.senary_hash,
}
SALT_SIZE = 16  # Salt size in bytes for cryptographic operations

# === Default Encryption Settings ===
ENCRYPTION_ALGORITHM = "AES"  # Default encryption algorithm for symmetric encryption
DEFAULT_KEY_SIZE = 256  # Default size for symmetric keys in bits
DEFAULT_IV_SIZE = 16  # Initialization Vector (IV) size in bytes for block ciphers

# === Logging & Error Handling Constants ===
LOGGING_DIRECTORY = "logs"  # Directory path for saving logs related to Seigr operations
ERROR_LOG_STRATEGY_DEFAULT = "LOG_AND_CONTINUE"  # Default error handling strategy for non-critical errors

# === Compliance & Audit Configuration ===
DEFAULT_RETENTION_PERIOD_DAYS = 90  # Retention period for audit and compliance logs
AUDIT_ARCHIVE_EXTENSION = ".enc"  # File extension for archived and encrypted audit logs
COMPLIANCE_ARCHIVE_PREFIX = f"{SEIGR_CELL_ID_PREFIX}_compliance_archive"

# === Integrity & Monitoring Configuration ===
INTEGRITY_CHECK_DEPTH = 4  # Default depth for hierarchical integrity checks
DEFAULT_MONITORING_INTERVAL = "10"  # Default interval (in senary format) for scheduled monitoring cycles
