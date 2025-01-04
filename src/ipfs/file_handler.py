import json
import logging

import requests

logger = logging.getLogger(__name__)


class FileHandler:
    def __init__(self, api_url):
        self.api_url = api_url

    def upload_data(self, data, filename="data", data_type="application/json"):
        try:
            files = {
                "file": (
                    filename,
                    data if isinstance(data, str) else json.dumps(data),
                    data_type,
                )
            }
            response = requests.post(f"{self.api_url}/add", files=files)
            response.raise_for_status()
            ipfs_hash = response.json().get("Hash")
            logger.info(f"Data uploaded to IPFS with hash: {ipfs_hash}")
            return ipfs_hash
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload data to IPFS: {e}")
            return None

    def retrieve_data(self, ipfs_hash, parse_json=True):
        try:
            response = requests.post(f"{self.api_url}/cat?arg={ipfs_hash}")
            response.raise_for_status()
            return json.loads(response.text) if parse_json else response.content
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve data from IPFS: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON data from IPFS: {e}")
            return None
