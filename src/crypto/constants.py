# src/crypto/constants.py

# === Core Seigr Protocol Identifiers ===
SEIGR_CELL_ID_PREFIX = "SEIGR"  # Identifier prefix for Seigr protocol entities
SEIGR_VERSION = "1.0"           # Protocol version for compatibility tracking

# === Cryptographic & Hashing Settings ===
DEFAULT_HASH_FUNCTION = "hypha_hash"  # Default hash function name as a string reference
SUPPORTED_HASH_ALGORITHMS = {
    "hypha_hash": "hypha_hash",
    "hypha_senary": "hypha_senary_hash",
}
SALT_SIZE = 16  # Salt size in bytes for cryptographic operations

# === Encryption Settings ===
ENCRYPTION_ALGORITHM = "AES"      # Default encryption algorithm
DEFAULT_KEY_SIZE = 256            # Symmetric key size in bits
DEFAULT_IV_SIZE = 16              # IV size for encryption algorithms

# === Logging & Error Handling Settings ===
LOGGING_DIRECTORY = "logs"                    # Default directory for logs
ERROR_LOG_STRATEGY_DEFAULT = "LOG_AND_CONTINUE"  # Default error-handling strategy

# === Compliance & Audit Settings ===
DEFAULT_RETENTION_PERIOD_DAYS = 90         # Default retention for compliance logs
AUDIT_ARCHIVE_EXTENSION = ".enc"           # Extension for encrypted audit archives
COMPLIANCE_ARCHIVE_PREFIX = f"{SEIGR_CELL_ID_PREFIX}_compliance_archive"

# === Integrity & Monitoring Settings ===
INTEGRITY_CHECK_DEPTH = 4            # Default depth for hierarchical integrity verification
DEFAULT_MONITORING_INTERVAL = "10"   # Senary interval for monitoring cycles
