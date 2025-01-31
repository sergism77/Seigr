import logging
from typing import List

from src.crypto.hash_utils import hypha_hash
from src.ipfs.ipfs_manager import IPFSManager  # ✅ Using IPFSManager from the ipfs/ module
from src.logger.secure_logger import secure_logger  # ✅ Corrected: Using Seigr's secure logging
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Using Seigr’s alert levels

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
        if not isinstance(seigr_id, str) or not seigr_id:
            raise ValueError("Seigr ID must be a non-empty string.")

        self.ipfs_manager = IPFSManager(seigr_id)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="IPFS",
            message=f"SeigrIPFSUtils initialized with Seigr ID: {seigr_id}",
        )

    def upload_lineage_segment(self, segment_data: bytes) -> str:
        """
        Uploads a single lineage segment to IPFS.

        Args:
            segment_data (bytes): The binary data of the lineage segment to be uploaded.

        Returns:
            str: The IPFS CID (Content Identifier) of the uploaded segment.

        Raises:
            IOError: If upload fails.
        """
        if not isinstance(segment_data, bytes) or not segment_data:
            raise ValueError("Segment data must be a valid non-empty bytes object.")

        try:
            cid = self.ipfs_manager.upload_data(
                segment_data,
                filename="lineage_segment",
                data_type="application/octet-stream",
            )
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="IPFS",
                message=f"Lineage segment uploaded to IPFS with CID: {cid}",
            )
            return cid
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="IPFS",
                message=f"Failed to upload lineage segment to IPFS: {e}",
            )
            raise IOError(f"IPFS upload failed: {e}")

    def fetch_lineage_segment(self, cid: str) -> bytes:
        """
        Fetches a specific lineage segment from IPFS by its CID.

        Args:
            cid (str): The CID of the lineage segment to retrieve.

        Returns:
            bytes: The binary data of the retrieved segment.

        Raises:
            IOError: If fetching fails.
        """
        if not isinstance(cid, str) or not cid:
            raise ValueError("CID must be a valid non-empty string.")

        try:
            segment_data = self.ipfs_manager.retrieve_data(cid, parse_json=False)
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="IPFS",
                message=f"Lineage segment fetched from IPFS with CID: {cid}",
            )
            return segment_data
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="IPFS",
                message=f"Failed to fetch lineage segment from IPFS with CID {cid}: {e}",
            )
            raise IOError(f"IPFS fetch failed for CID {cid}: {e}")

    def validate_ipfs_storage(self, cid: str, expected_hash: str) -> bool:
        """
        Validates the integrity of a stored IPFS file by comparing its hash.

        Args:
            cid (str): The CID of the IPFS file.
            expected_hash (str): The expected hash of the file for verification.

        Returns:
            bool: True if the file's hash matches the expected hash, False otherwise.

        Raises:
            IOError: If validation fails due to fetch or hash calculation issues.
        """
        if not isinstance(cid, str) or not cid:
            raise ValueError("CID must be a valid non-empty string.")
        if not isinstance(expected_hash, str) or not expected_hash:
            raise ValueError("Expected hash must be a valid non-empty string.")

        try:
            segment_data = self.fetch_lineage_segment(cid)
            computed_hash = hypha_hash(segment_data)

            if computed_hash == expected_hash:
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_INFO,
                    category="IPFS",
                    message=f"Validation successful for IPFS CID {cid}",
                )
                return True
            else:
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                    category="IPFS",
                    message=f"Hash mismatch for IPFS CID {cid}. Expected {expected_hash}, got {computed_hash}",
                )
                return False
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="IPFS",
                message=f"Failed to validate IPFS storage for CID {cid}: {e}",
            )
            raise IOError(f"IPFS validation failed for CID {cid}: {e}")

    def list_lineage_cids(self, lineage_segments: List[bytes]) -> List[str]:
        """
        Lists the CIDs of lineage segments stored on IPFS.

        Args:
            lineage_segments (List[bytes]): List of binary data segments in the lineage.

        Returns:
            List[str]: List of CIDs corresponding to the lineage segments.

        Raises:
            IOError: If any segment upload fails.
        """
        if not isinstance(lineage_segments, list) or not all(isinstance(seg, bytes) for seg in lineage_segments):
            raise ValueError("lineage_segments must be a list of valid bytes objects.")

        cids = []
        for segment in lineage_segments:
            try:
                cid = self.upload_lineage_segment(segment)
                cids.append(cid)
            except Exception as e:
                secure_logger.log_audit_event(
                    severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                    category="IPFS",
                    message=f"Failed to upload lineage segment to IPFS: {e}",
                )
                continue
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="IPFS",
            message=f"List of CIDs for lineage segments: {cids}",
        )
        return cids

    def compute_cid(self, data: bytes) -> str:
        """
        Computes the CID for given data by uploading temporarily to IPFS without persistence.

        Args:
            data (bytes): The data to compute the CID for.

        Returns:
            str: The computed CID for the provided data.

        Raises:
            IOError: If CID computation fails.
        """
        if not isinstance(data, bytes) or not data:
            raise ValueError("Data must be a valid non-empty bytes object.")

        try:
            cid = self.ipfs_manager.upload_data(
                data, filename="temp_segment", data_type="application/octet-stream"
            )
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="IPFS",
                message=f"Computed CID for provided data: {cid}",
            )
            return cid
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="IPFS",
                message=f"Failed to compute CID for data: {e}",
            )
            raise IOError(f"Failed to compute CID: {e}")
