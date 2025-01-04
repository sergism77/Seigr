import logging
from typing import List

from src.crypto.hash_utils import hypha_hash
from src.ipfs.ipfs_manager import IPFSManager  # Using IPFSManager from the ipfs/ module

logger = logging.getLogger(__name__)


class SeigrIPFSUtils:
    """
    Utility class for managing interactions with IPFS, handling uploads, downloads,
    and integrity validations for lineage segments within the Seigr ecosystem.
    """

    def __init__(self, seigr_id: str):
        """
        Initializes SeigrIPFSUtils with an IPFSManager instance for interacting with IPFS.

        Args:
            seigr_id (str): Identifier for the Seigr system instance, for session tracking.
        """
        self.ipfs_manager = IPFSManager(seigr_id)
        logger.info(f"SeigrIPFSUtils initialized with Seigr ID: {seigr_id}")

    def upload_lineage_segment(self, segment_data: bytes) -> str:
        """
        Uploads a single lineage segment to IPFS.

        Args:
            segment_data (bytes): The binary data of the lineage segment to be uploaded.

        Returns:
            str: The IPFS CID (Content Identifier) of the uploaded segment.

        Raises:
            Exception: If upload fails.
        """
        try:
            cid = self.ipfs_manager.upload_data(
                segment_data,
                filename="lineage_segment",
                data_type="application/octet-stream",
            )
            logger.info(f"Lineage segment uploaded to IPFS with CID: {cid}")
            return cid
        except Exception as e:
            logger.error(f"Failed to upload lineage segment to IPFS: {e}")
            raise

    def fetch_lineage_segment(self, cid: str) -> bytes:
        """
        Fetches a specific lineage segment from IPFS by its CID.

        Args:
            cid (str): The CID of the lineage segment to retrieve.

        Returns:
            bytes: The binary data of the retrieved segment.

        Raises:
            Exception: If fetching fails.
        """
        try:
            segment_data = self.ipfs_manager.retrieve_data(cid, parse_json=False)
            logger.info(f"Lineage segment fetched from IPFS with CID: {cid}")
            return segment_data
        except Exception as e:
            logger.error(
                f"Failed to fetch lineage segment from IPFS with CID {cid}: {e}"
            )
            raise

    def validate_ipfs_storage(self, cid: str, expected_hash: str) -> bool:
        """
        Validates the integrity of a stored IPFS file by comparing its hash.

        Args:
            cid (str): The CID of the IPFS file.
            expected_hash (str): The expected hash of the file for verification.

        Returns:
            bool: True if the file's hash matches the expected hash, False otherwise.

        Raises:
            Exception: If validation fails due to fetch or hash calculation issues.
        """
        try:
            segment_data = self.fetch_lineage_segment(cid)
            computed_hash = hypha_hash(segment_data)

            if computed_hash == expected_hash:
                logger.info(f"Validation successful for IPFS CID {cid}")
                return True
            else:
                logger.warning(
                    f"Hash mismatch for IPFS CID {cid}. Expected {expected_hash}, got {computed_hash}"
                )
                return False
        except Exception as e:
            logger.error(f"Failed to validate IPFS storage for CID {cid}: {e}")
            raise

    def list_lineage_cids(self, lineage_segments: List[bytes]) -> List[str]:
        """
        Lists the CIDs of lineage segments stored on IPFS.

        Args:
            lineage_segments (List[bytes]): List of binary data segments in the lineage.

        Returns:
            List[str]: List of CIDs corresponding to the lineage segments.

        Raises:
            Exception: If any segment upload fails.
        """
        cids = []
        for segment in lineage_segments:
            try:
                cid = self.upload_lineage_segment(segment)
                cids.append(cid)
            except Exception as e:
                logger.error(f"Failed to upload lineage segment to IPFS: {e}")
                continue
        logger.debug(f"List of CIDs for lineage segments: {cids}")
        return cids

    def compute_cid(self, data: bytes) -> str:
        """
        Computes the CID for given data by uploading temporarily to IPFS without persistence.

        Args:
            data (bytes): The data to compute the CID for.

        Returns:
            str: The computed CID for the provided data.

        Raises:
            Exception: If CID computation fails.
        """
        try:
            cid = self.ipfs_manager.upload_data(
                data, filename="temp_segment", data_type="application/octet-stream"
            )
            logger.info(f"Computed CID for provided data: {cid}")
            return cid
        except Exception as e:
            logger.error(f"Failed to compute CID for data: {e}")
            raise
