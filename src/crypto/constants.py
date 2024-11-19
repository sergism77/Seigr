# src/crypto/constants.py

# === Core Seigr Protocol Identifiers ===
SEIGR_CELL_ID_PREFIX = "SEIGR"  # Identifier prefix for Seigr protocol entities
SEIGR_VERSION = "1.0"  # Protocol version for compatibility tracking
SEIGR_METADATA_PROTOCOL = (
    "Seigr"  # Protocol tag for metadata to ensure uniform recognition
)

# === Cryptographic & Hashing Settings ===
DEFAULT_HASH_FUNCTION = "hypha_hash"  # Default hash function used throughout Seigr
SUPPORTED_HASH_ALGORITHMS = {
    "hypha_hash": "hypha_hash",  # Default hybrid hash method
    "hypha_senary": "hypha_senary_hash",  # Senary-based hashing alternative
}
SALT_SIZE = 16  # Salt size in bytes for cryptographic operations

# === Encryption Settings ===
ENCRYPTION_ALGORITHM = "AES"  # Default encryption algorithm for symmetric operations
DEFAULT_KEY_SIZE = 256  # Symmetric key size in bits for robust security
DEFAULT_IV_SIZE = 16  # IV size in bytes for AES encryption

# === Logging & Error Handling Settings ===
LOGGING_DIRECTORY = "logs"  # Default directory for logs
ERROR_LOG_STRATEGY_DEFAULT = "LOG_AND_CONTINUE"  # Default strategy for error handling
DEFAULT_ERROR_SEVERITY = "MEDIUM"  # Default severity level for logged errors
ALERT_CRITICAL_THRESHOLD = 3  # Threshold for triggering critical alerts

# === Compliance & Audit Settings ===
DEFAULT_RETENTION_PERIOD_DAYS = 90  # Default retention period for audit logs in days
AUDIT_ARCHIVE_EXTENSION = ".enc"  # File extension for encrypted audit archives
COMPLIANCE_ARCHIVE_PREFIX = f"{SEIGR_CELL_ID_PREFIX}_compliance_archive"
SECURE_ARCHIVE_ENCRYPTION_KEY_SIZE = 256  # Key size for encryption of archived logs

# === Integrity & Monitoring Settings ===
INTEGRITY_CHECK_DEPTH = 4  # Depth level for hierarchical integrity verification
DEFAULT_MONITORING_INTERVAL_SENARY = "10"  # Senary-based interval for monitoring cycles
MAX_INTEGRITY_RETRIES = 2  # Maximum retries for integrity checks

# === Senary Encoding & Protocol Settings ===
SENARY_BASE = 6  # Base for Seigr’s senary encoding
SENARY_ENCODING_PREFIX = "6E"  # Prefix for encoding senary values
