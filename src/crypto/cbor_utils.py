import logging
import uuid
from datetime import datetime, timezone

import cbor2

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import decode_from_senary, encode_to_senary, is_senary
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.logger.base_logger import base_logger

logger = logging.getLogger(__name__)


# 🛡️ Alert Trigger
def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert event with structured logging and protocol compliance.
    """
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
        AlertSeverity.Name(severity),
    )
    base_logger.log_message(
        level='CRITICAL' if severity == AlertSeverity.ALERT_SEVERITY_CRITICAL else 'WARNING',
        message=message,
        category="Alert",
        sensitive=False
    )


# 🔄 Data Transformation
def transform_data(value, use_senary=False):
    """
    Transforms data for CBOR encoding/decoding.
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
    Encodes data into CBOR format with optional senary transformation.
    """
    try:
        encoded = cbor2.dumps(data)
        base_logger.log_message(
            level='INFO',
            message='Data successfully encoded to CBOR format',
            category='Encode',
            sensitive=False
        )
        return EncryptedData(ciphertext=encoded)
    except Exception as e:
        _trigger_alert(f"CBOR encoding error: {str(e)}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("CBOR encoding error occurred") from e


# 🛠️ CBOR Decoding
def decode_data(encrypted_data: EncryptedData, use_senary=False):
    """
    Decodes CBOR-encoded data from EncryptedData protobuf structure.
    """
    if not encrypted_data or not encrypted_data.ciphertext:
        base_logger.log_message(
            level='ERROR',
            message='Invalid EncryptedData object for decoding',
            category='Decode',
            sensitive=False
        )
        raise ValueError("Invalid EncryptedData object for decoding")
    
    try:
        decoded = cbor2.loads(encrypted_data.ciphertext)
        base_logger.log_message(
            level='INFO',
            message='Data successfully decoded from CBOR format',
            category='Decode',
            sensitive=False
        )
        return decoded
    except cbor2.CBORDecodeError as e:
        _trigger_alert(f"CBOR decode error: {str(e)}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("CBOR decode error") from e
    except Exception as e:
        _trigger_alert(f"CBOR decoding exception: {str(e)}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("CBOR decoding failed") from e


# 💾 Save to File
def save_to_file(data, file_path, use_senary=False):
    """
    Saves encoded CBOR data to a file.
    """
    try:
        encoded_data = encode_data(data, use_senary=use_senary)
        with open(file_path, "wb") as file:
            file.write(encoded_data.ciphertext)
        base_logger.log_message(
            level='INFO',
            message=f'Data successfully saved to file: {file_path}',
            category='FileIO',
            sensitive=False
        )
    except Exception as e:
        _trigger_alert(f"Failed to save data to file: {file_path}. Error: {str(e)}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise IOError("Failed to save file") from e


# 💾 Load from File
def load_from_file(file_path: str):
    """
    Loads CBOR-encoded data from a file.
    """
    try:
        with open(file_path, "rb") as file:
            encrypted_data = EncryptedData(ciphertext=file.read())
        decoded_data = decode_data(encrypted_data)
        base_logger.log_message(
            level='INFO',
            message=f'Data successfully loaded from file: {file_path}',
            category='FileIO',
            sensitive=False
        )
        return decoded_data
    except Exception as e:
        _trigger_alert(f"Failed to load data from file: {file_path}. Error: {str(e)}", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise IOError("Failed to load file") from e
