# src/ipfs/api_connector.py

import requests
import logging

logger = logging.getLogger(__name__)
IPFS_API_URL = "http://127.0.0.1:5001/api/v0"

class APIConnector:
    def __init__(self):
        self.api_url = IPFS_API_URL
        self.connected = self.check_connection()

    def check_connection(self):
        try:
            response = requests.post(f"{self.api_url}/id")
            if response.status_code == 200:
                logger.info("Connected to IPFS HTTP API successfully.")
                return True
            else:
                logger.error("Failed to connect to IPFS HTTP API.")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to IPFS HTTP API: {e}")
            return False
