# src/ipfs/ipfs_manager.py

import logging
from src.ipfs.daemon_manager import DaemonManager
from src.ipfs.api_connector import APIConnector
from src.ipfs.file_handler import FileHandler
from src.ipfs.session_tracker import SessionTracker

logger = logging.getLogger(__name__)

class IPFSManager:
    def __init__(self, seigr_id):
        self.seigr_id = seigr_id
        self.daemon_manager = DaemonManager()
        self.api_connector = APIConnector()
        self.file_handler = FileHandler(self.api_connector.api_url)
        self.session_tracker = SessionTracker()

        if not self.api_connector.connected:
            logger.warning("IPFSManager: Unable to connect to IPFS API.")

    def start_daemon(self):
        return self.daemon_manager.start_ipfs_daemon()

    def stop_daemon(self):
        self.daemon_manager.stop_ipfs_daemon()

    def upload_json(self, data):
        if not self.api_connector.connected:
            raise ConnectionError("IPFS HTTP API is not connected.")
        return self.file_handler.upload_json(data)

    def retrieve_json(self, ipfs_hash):
        if not self.api_connector.connected:
            raise ConnectionError("IPFS HTTP API is not connected.")
        return self.file_handler.retrieve_json(ipfs_hash)

    def track_session_duration(self):
        self.session_tracker.track_session_duration()
