import logging
import uuid
from datetime import datetime, timezone

import cbor2

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import decode_from_senary, encode_to_senary, is_senary
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.crypto.secure_logging import _secure_logger_instance

logger = logging.getLogger(__name__)


# 🛡️ Alert Trigger
def _trigger_alert(message: str, severity: int) -> None:
    """
    Trigger an alert for critical failures.

    Args:
        message (str): Description of the alert.
        severity (int): Severity level as defined in AlertSeverity enum.

    Raises:
        None
    """
    severity_enum = AlertSeverity.Name(severity) if severity in AlertSeverity.values() else "ALERT_SEVERITY_UNSPECIFIED"
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        message=message,
        type=AlertType.ALERT_TYPE_DATA_INTEGRITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="cbor_utils",
    )
    logger.warning(
        "%s Alert triggered: %s with severity %s",
        SEIGR_CELL_ID_PREFIX,
        alert.message,
        severity_enum,
    )
    if _secure_logger_instance:
        _secure_logger_instance.log_audit_event(
            severity=severity,
            category="Alert",
            message=message,
            sensitive=False,
            use_senary=False,
        )


# 🔄 Data Transformation
def transform_data(value, use_senary=False):
    """
    Transform data recursively based on type.

    Args:
        value: Data to be transformed.
        use_senary (bool): Whether to encode/decode using senary encoding.

    Returns:
        Transformed data based on type.

    Raises:
        TypeError: If the data type is unsupported.
    """
    if isinstance(value, bytes):
        return encode_to_senary(value) if use_senary else value
    if isinstance(value, dict):
        return {k: transform_data(v, use_senary) for k, v in value.items()}
    if isinstance(value, list):
        return [transform_data(v, use_senary) for v in value]
    if isinstance(value, str):
        return decode_from_senary(value) if use_senary and is_senary(value) else value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported data type: {type(value).__name__}")


# 📝 CBOR Encoding
def encode_data(data, use_senary=False) -> EncryptedData:
    """
    Encode data into CBOR format and wrap it in an EncryptedData object.

    Args:
        data: The data to encode.
        use_senary (bool): Whether to use senary encoding.

    Returns:
        EncryptedData: Encoded data wrapped in EncryptedData object.

    Raises:
        ValueError: If encoding fails.
    """
    try:
        transformed_data = transform_data(data, use_senary=use_senary)
        encoded = cbor2.dumps(transformed_data)
        if _secure_logger_instance:
            _secure_logger_instance.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Encode",
                message="Data successfully encoded to CBOR format",
                sensitive=False,
                use_senary=use_senary,
            )
        return EncryptedData(ciphertext=encoded)
    except Exception as e:
        _trigger_alert(f"Encoding failed: {e}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("CBOR encoding error occurred") from e


# 🛠️ CBOR Decoding
def decode_data(encrypted_data: EncryptedData, use_senary=False):
    """
    Decode CBOR data from an EncryptedData object.

    Args:
        encrypted_data (EncryptedData): The encrypted data object.
        use_senary (bool): Whether to use senary encoding.

    Returns:
        Decoded and transformed data.

    Raises:
        ValueError: If decoding fails or data is invalid.
    """
    if not encrypted_data or not encrypted_data.ciphertext:
        _trigger_alert("Invalid EncryptedData object for decoding", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("Invalid EncryptedData object for decoding")
    try:
        decoded = cbor2.loads(encrypted_data.ciphertext)
        transformed = transform_data(decoded, use_senary=use_senary)
        if _secure_logger_instance:
            _secure_logger_instance.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Decode",
                message="Data successfully decoded from CBOR format",
                sensitive=False,
                use_senary=use_senary,
            )
        return transformed
    except cbor2.CBORDecodeError as e:
        _trigger_alert(f"CBOR decode error: {e}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("CBOR decode error") from e


# 💾 Save to File
def save_to_file(data, file_path, use_senary=False):
    """
    Save data to a CBOR file.

    Args:
        data: Data to be saved.
        file_path (str): Path to save the file.
        use_senary (bool): Whether to use senary encoding.

    Raises:
        IOError: If saving fails.
    """
    try:
        encoded_data = encode_data(data, use_senary=use_senary)
        with open(file_path, "wb") as file:
            file.write(encoded_data.ciphertext)
    except Exception as e:
        _trigger_alert(f"Failed to save data to file: {file_path}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise IOError("Failed to save file") from e


# 💾 Load from File
def load_from_file(file_path: str):
    """
    Load and decode data from a CBOR file.

    Args:
        file_path (str): Path to load the file from.

    Returns:
        Decoded data.

    Raises:
        IOError: If loading fails.
    """
    try:
        with open(file_path, "rb") as file:
            encrypted_data = EncryptedData(ciphertext=file.read())
        return decode_data(encrypted_data)
    except Exception as e:
        _trigger_alert(f"Failed to load data from file: {file_path}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise IOError("Failed to load file") from e
