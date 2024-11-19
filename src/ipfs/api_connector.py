import requests
import logging
from time import sleep

logger = logging.getLogger(__name__)
IPFS_API_URL = "http://127.0.0.1:5001/api/v0"


class APIConnector:
    def __init__(self, retry_count=3, retry_delay=2):
        self.api_url = IPFS_API_URL
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.connected = self.check_connection()

    def check_connection(self):
        for attempt in range(self.retry_count):
            try:
                response = requests.post(f"{self.api_url}/id")
                if response.status_code == 200:
                    logger.info("Connected to IPFS HTTP API successfully.")
                    return True
            except requests.exceptions.RequestException as e:
                logger.error(f"Connection attempt {attempt + 1} failed: {e}")
                sleep(self.retry_delay)
        logger.error("Failed to connect to IPFS HTTP API after retries.")
        return False

    def request(self, endpoint, method="POST", **kwargs):
        try:
            url = f"{self.api_url}/{endpoint}"
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"IPFS API request to {url} failed: {e}")
            return None
