import logging
import os

# ✅ Ensure environment variable retrieval is properly handled with default fallbacks

# Dynamic Log Level (fallback to DEBUG if not set)
LOG_LEVEL = os.getenv("SEIGR_LOG_LEVEL", "DEBUG").upper()
LOG_LEVEL = getattr(logging, LOG_LEVEL, logging.DEBUG)  # ✅ Ensure valid log level

# Log Format
LOG_FORMAT = os.getenv("SEIGR_LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Log File Path (fallback to default)
LOG_FILE = os.getenv("SEIGR_LOG_FILE", "seigr_app.log")

# Log Rotation Settings (Ensure valid integers)
try:
    LOG_ROTATION_MAX_BYTES = int(os.getenv("SEIGR_LOG_ROTATION_MAX_BYTES", 10**6))  # Default: 1 MB
except ValueError:
    LOG_ROTATION_MAX_BYTES = 10**6  # ✅ Fallback to default if conversion fails

try:
    LOG_ROTATION_BACKUP_COUNT = int(
        os.getenv("SEIGR_LOG_ROTATION_BACKUP_COUNT", 3)
    )  # Default: 3 backups
except ValueError:
    LOG_ROTATION_BACKUP_COUNT = 3  # ✅ Fallback to default if conversion fails

# Sensitive Keywords for Redaction (default keywords with optional environment override)
SENSITIVE_KEYWORDS = os.getenv("SEIGR_SENSITIVE_KEYWORDS", "password,secret,token")
SENSITIVE_KEYWORDS = [
    word.strip() for word in SENSITIVE_KEYWORDS.split(",") if word.strip()
]  # ✅ Clean & sanitize

# ✅ Debugging log level handling
if LOG_LEVEL not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
    logging.warning(f"⚠️ WARNING: Invalid LOG_LEVEL `{LOG_LEVEL}`, defaulting to DEBUG.")
    LOG_LEVEL = logging.DEBUG  # ✅ Enforce fallback to DEBUG if invalid
