import logging

from src.ipfs.api_connector import APIConnector
from src.ipfs.daemon_manager import DaemonManager
from src.ipfs.file_handler import FileHandler
from src.ipfs.session_tracker import SessionTracker

logger = logging.getLogger(__name__)


class IPFSManager:
    def __init__(self, seigr_id, ipfs_path="ipfs"):
        self.seigr_id = seigr_id
        self.daemon_manager = DaemonManager(ipfs_path=ipfs_path)
        self.api_connector = APIConnector()
        self.file_handler = FileHandler(self.api_connector.api_url)
        self.session_tracker = SessionTracker()

        if not self.api_connector.connected:
            logger.warning("IPFSManager: Unable to connect to IPFS API.")

    def start_daemon(self):
        return self.daemon_manager.start_ipfs_daemon()

    def stop_daemon(self):
        self.daemon_manager.stop_ipfs_daemon()

    def upload_data(self, data, filename="data", data_type="application/json"):
        if not self.api_connector.connected:
            raise ConnectionError("IPFS HTTP API is not connected.")
        return self.file_handler.upload_data(data, filename, data_type)

    def retrieve_data(self, ipfs_hash, parse_json=True):
        if not self.api_connector.connected:
            raise ConnectionError("IPFS HTTP API is not connected.")
        return self.file_handler.retrieve_data(ipfs_hash, parse_json)

    def track_session_duration(self):
        self.session_tracker.track_session_duration()
