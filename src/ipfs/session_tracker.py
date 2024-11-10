# src/ipfs/session_tracker.py

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SessionTracker:
    def __init__(self):
        self.start_time = datetime.now()

    def track_session_duration(self):
        duration = datetime.now() - self.start_time
        logger.info(f"IPFS session lasted {duration}.")
