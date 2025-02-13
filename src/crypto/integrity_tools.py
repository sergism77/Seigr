"""
📌 **Integrity Tools Module**
Handles **integrity verification**, **hash comparisons**, and **logging**
in accordance with **Seigr security standards**.
"""

import logging
from src.crypto.helpers import decode_from_senary
from src.crypto.hypha_crypt import HyphaCrypt  # ✅ Now imported here!
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

logger = logging.getLogger(__name__)


def verify_integrity(
    data: bytes = None,
    computed_hash: str = None,
    expected_hash: str = None,
    salt: str = None,
    senary_encoded: bool = False
) -> bool:
    """
    **Verifies data integrity by comparing computed and expected hashes.**
    
    Supports both **Senary and traditional hash formats**.

    Args:
        data (bytes, optional): **The original data to compute the hash from.**
        computed_hash (str, optional): **If provided, skips computing hash from data.**
        expected_hash (str): **The expected hash to compare against.**
        salt (str, optional): **Optional salt used in hashing.**
        senary_encoded (bool, optional): **Set to True if expected hash is in Senary format.**

    Returns:
        bool: **True if hashes match, False otherwise.**
    """
    try:
        # ✅ If computed_hash is not provided, compute from data
        if computed_hash is None:
            if data is None:
                raise ValueError("Either `data` or `computed_hash` must be provided.")

            hypha_crypt = HyphaCrypt(data=data, segment_id="integrity_verification")
            computed_hash = hypha_crypt.HASH_SEIGR_SENARY(data, salt=salt)

        # ✅ Decode Senary hash if necessary
        if senary_encoded:
            expected_hash = decode_from_senary(expected_hash)

        # ✅ Compare hashes
        match = computed_hash == expected_hash

        # ✅ Log the verification attempt
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO if match else AlertSeverity.ALERT_SEVERITY_WARNING,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Integrity verification {'successful' if match else 'failed'}.",
            log_data={"expected_hash": expected_hash, "computed_hash": computed_hash, "match": match},
        )

        return match

    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Integrity verification failed.",
            log_data={"error": str(e)},
            sensitive=False,
        )
        raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Integrity verification failed.") from e
