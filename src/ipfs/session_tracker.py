import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SessionTracker:
    def __init__(self):
        self.start_time = datetime.now()
        self.session_history = []

    def track_session_duration(self):
        duration = datetime.now() - self.start_time
        logger.info(f"Current IPFS session lasted {duration}.")
        self.session_history.append({"start": self.start_time, "duration": duration})
        self.start_time = datetime.now()  # Reset for the next session

    def get_session_history(self):
        return self.session_history
