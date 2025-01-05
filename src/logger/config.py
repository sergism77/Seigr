# src/logger/config.py

import logging

# Log Levels - Align with Protobuf Severity Enum
LOG_LEVEL = logging.DEBUG  # Or set dynamically via env variables/config files
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Log Destination (Example: File and Console)
LOG_FILE = "seigr_app.log"
