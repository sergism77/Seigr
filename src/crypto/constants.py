# src/crypto/constants.py
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm

# === Core Seigr Protocol Identifiers ===
SEIGR_CELL_ID_PREFIX = "SEIGR"  # Identifier prefix for Seigr protocol entities
SEIGR_VERSION = "1.0"  # Protocol version for compatibility tracking
SEIGR_METADATA_PROTOCOL = "Seigr"  # Protocol tag for metadata to ensure uniform recognition

# === Cryptographic & Hashing Settings ===
DEFAULT_HASH_FUNCTION = "HASH_SEIGR_SENARY"  # Default hash function used throughout Seigr
SUPPORTED_HASH_ALGORITHMS = {
    "hypha_hash": HashAlgorithm.HASH_SEIGR_SENARY,  # ✅ Keep existing entry
    "HASH_SEIGR_SENARY": HashAlgorithm.HASH_SEIGR_SENARY,  # ✅ Add uppercase version
    "hash_seigr_senary": HashAlgorithm.HASH_SEIGR_SENARY,  # ✅ Add lowercase version
}

SALT_SIZE = 16  # Salt size in bytes for cryptographic operations
DEFAULT_ITERATIONS = 100000  # Default PBKDF2 iterations for key derivation
DEFAULT_KEY_DERIVATION_ALGORITHM = "PBKDF2-HMAC-SHA256"  # Default key derivation algorithm

# === Encryption Settings ===
ENCRYPTION_ALGORITHM = "AES"  # Default encryption algorithm for symmetric operations
DEFAULT_KEY_SIZE = 256  # Symmetric key size in bits for robust security
DEFAULT_IV_SIZE = 16  # IV size in bytes for AES encryption
ASYMMETRIC_KEY_SIZE = 2048  # Default RSA key size for asymmetric encryption
ASYMMETRIC_ALGORITHM = "RSA"  # Default algorithm for asymmetric encryption
ENCRYPTION_PADDING = "PSS"  # Default padding scheme for asymmetric encryption
ENCRYPTION_HASH_ALGORITHM = (
    "HASH_SEIGR_SENARY"  # Preferred hashing algorithm for encryption validation
)

# === Error Severity Levels (Using Correct Protobuf Definitions) ===
ALERT_SEVERITY_UNDEFINED = AlertSeverity.ALERT_SEVERITY_UNDEFINED  # Undefined severity
ALERT_SEVERITY_INFO = AlertSeverity.ALERT_SEVERITY_INFO  # Informational messages
ALERT_SEVERITY_WARNING = AlertSeverity.ALERT_SEVERITY_WARNING  # Warnings that may require attention
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity

print("DEBUG ENUM:", list(AlertSeverity.keys()))  # TEMP DEBUG
ALERT_SEVERITY_CRITICAL = AlertSeverity.ALERT_SEVERITY_CRITICAL  # 🔹 MISSING VALUE (Now Added)
ALERT_SEVERITY_ERROR = (
    AlertSeverity.ALERT_SEVERITY_ERROR
)  # High-priority errors requiring immediate response
ALERT_SEVERITY_CRITICAL = (
    AlertSeverity.ALERT_SEVERITY_CRITICAL
)  # Critical failures that could impact system integrity
ALERT_SEVERITY_FATAL = (
    AlertSeverity.ALERT_SEVERITY_FATAL
)  # Fatal system errors requiring immediate intervention

# === Default Logging & Error Handling Settings ===
LOGGING_DIRECTORY = "logs"  # Default directory for logs
LOG_FILE_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
ERROR_LOG_STRATEGY_DEFAULT = "LOG_AND_CONTINUE"  # Default strategy for error handling
DEFAULT_ERROR_SEVERITY = ALERT_SEVERITY_WARNING  # Aligning with standardized severity constants
ALERT_CRITICAL_THRESHOLD = 3  # Threshold for triggering critical alerts

# Enhanced Logging Categories
LOG_CATEGORIES = {
    "SECURITY": "Security",
    "INTEGRITY": "Integrity",
    "SYSTEM": "System",
    "GENERAL": "General",
    "AUDIT": "Audit",
}

# Enhanced Log Levels
LOG_LEVELS = {
    "INFO": "Information",
    "DEBUG": "Debugging",
    "WARNING": "Warning",
    "ERROR": "Error",
    "CRITICAL": "Critical",
}

# === Compliance & Audit Settings ===
DEFAULT_RETENTION_PERIOD_DAYS = 90  # Default retention period for audit logs in days
AUDIT_ARCHIVE_EXTENSION = ".enc"  # File extension for encrypted audit archives
COMPLIANCE_ARCHIVE_PREFIX = f"{SEIGR_CELL_ID_PREFIX}_compliance_archive"
SECURE_ARCHIVE_ENCRYPTION_KEY_SIZE = 256  # Key size for encryption of archived logs
AUDIT_METADATA_PROTOCOL = "Seigr_Audit"  # Protocol tag for audit metadata

# === Integrity & Monitoring Settings ===
INTEGRITY_CHECK_DEPTH = 4  # Depth level for hierarchical integrity verification
DEFAULT_MONITORING_INTERVAL_SENARY = "10"  # Senary-based interval for monitoring cycles
MAX_INTEGRITY_RETRIES = 2  # Maximum retries for integrity checks
INTEGRITY_HASH_ALGORITHM = "hypha_senary"  # Algorithm for integrity hashing
DEFAULT_VERIFICATION_STRATEGY = "HIERARCHICAL"  # Default verification strategy for integrity checks

# === Senary Encoding & Protocol Settings ===
SENARY_BASE = 6  # Base for Seigr’s senary encoding
SENARY_ENCODING_PREFIX = "6E"  # Prefix for encoding senary values
DEFAULT_SENARY_ENCODING = True  # Enable senary encoding by default
SENARY_INTEGRITY_DEPTH = 3  # Default senary integrity verification depth

# === Alerting and Monitoring Defaults ===
ALERT_DEFAULT_STRATEGY = "ALERT_AND_PAUSE"  # Default alerting strategy
MAX_ALERT_RETRIES = 5  # Maximum retries for alert escalation
DEFAULT_MONITORING_STRATEGY = "CYCLIC"  # Default monitoring cycle strategy
DEFAULT_MONITORING_INTERVAL = 60  # Monitoring interval in seconds

# === Metadata & Lifecycle Defaults ===
DEFAULT_METADATA_CONTEXT = "Seigr_Operation"  # Default metadata context for operations
DEFAULT_LIFECYCLE_STATUS = "active"  # Default lifecycle status for keys and entities
DEFAULT_ROTATION_POLICY = "annual"  # Default rotation policy for keys

# === Security Policies ===
SECURITY_POLICY_VERSION = "1.0"
SECURITY_POLICY_HASH_ALGORITHM = "hypha_senary"
DEFAULT_ACCESS_CONTROL_POLICY = "Role-Based Access Control (RBAC)"
SECURITY_EVENT_LOGGING = True  # Enable security event logging by default

# === Thresholds ===
INTEGRITY_FAILURE_THRESHOLD = 2  # Number of allowed integrity failures before escalation
ENCRYPTION_FAILURE_THRESHOLD = 3  # Number of encryption failures before triggering alerts
