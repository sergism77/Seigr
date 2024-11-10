# src/ipfs/file_handler.py

import requests
import json
import logging

logger = logging.getLogger(__name__)

class FileHandler:
    def __init__(self, api_url):
        self.api_url = api_url

    def upload_json(self, data):
        try:
            files = {'file': ('data.json', json.dumps(data), 'application/json')}
            response = requests.post(f"{self.api_url}/add", files=files)
            response.raise_for_status()
            ipfs_hash = response.json().get('Hash')
            logger.info(f"Data uploaded to IPFS with hash: {ipfs_hash}")
            return ipfs_hash
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload JSON data to IPFS: {e}")
            return None

    def retrieve_json(self, ipfs_hash):
        try:
            response = requests.post(f"{self.api_url}/cat?arg={ipfs_hash}")
            response.raise_for_status()
            data = json.loads(response.text)
            logger.info("Data retrieved from IPFS successfully.")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve JSON data from IPFS: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON data from IPFS: {e}")
            return None
