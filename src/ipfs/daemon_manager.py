import atexit
import logging
import subprocess
import time
from datetime import datetime

logger = logging.getLogger(__name__)
_ipfs_process = None


class DaemonManager:
    def __init__(self, ipfs_path="ipfs"):
        self.ipfs_path = ipfs_path
        self.start_time = None

    def start_ipfs_daemon(self):
        global _ipfs_process
        if _ipfs_process is not None:
            logger.warning("IPFS daemon is already running.")
            return False

        logger.info("Starting local IPFS daemon...")
        try:
            _ipfs_process = subprocess.Popen(
                [self.ipfs_path, "daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(5)  # Allow time for the daemon to initialize

            if _ipfs_process.poll() is None:
                self.start_time = datetime.now()
                atexit.register(self.stop_ipfs_daemon)
                logger.info("IPFS daemon started successfully.")
                return True
            else:
                stdout, stderr = _ipfs_process.communicate()
                logger.error(f"IPFS daemon failed to start: {stderr.decode().strip()}")
                _ipfs_process = None
                return False
        except Exception as e:
            logger.error(f"Failed to start IPFS daemon: {e}")
            return False

    def stop_ipfs_daemon(self):
        global _ipfs_process
        if _ipfs_process is not None:
            _ipfs_process.terminate()
            _ipfs_process.wait()
            duration = (
                datetime.now() - self.start_time
                if self.start_time
                else "unknown duration"
            )
            logger.info(f"Stopped IPFS daemon after {duration}.")
            _ipfs_process = None
        else:
            logger.warning("No IPFS daemon process to stop.")
