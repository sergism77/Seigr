import logging
import os

# Dynamic Log Level (fallback to DEBUG if not set)
LOG_LEVEL = getattr(logging, os.getenv("SEIGR_LOG_LEVEL", "DEBUG").upper(), logging.DEBUG)

# Log Format
LOG_FORMAT = os.getenv(
    "SEIGR_LOG_FORMAT",
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Log File Path (fallback to default)
LOG_FILE = os.getenv("SEIGR_LOG_FILE", "seigr_app.log")

# Log Rotation Settings
LOG_ROTATION_MAX_BYTES = int(os.getenv("SEIGR_LOG_ROTATION_MAX_BYTES", 10**6))  # 1 MB
LOG_ROTATION_BACKUP_COUNT = int(os.getenv("SEIGR_LOG_ROTATION_BACKUP_COUNT", 3))  # 3 backups

# Sensitive Keywords for Redaction (default keywords with optional environment override)
SENSITIVE_KEYWORDS = os.getenv(
    "SEIGR_SENSITIVE_KEYWORDS",
    "password,secret,token"
).split(",")
