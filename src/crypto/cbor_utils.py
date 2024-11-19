import cbor2
import logging
import uuid
from datetime import datetime, timezone
from src.crypto.helpers import encode_to_senary, decode_from_senary, is_senary
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

logger = logging.getLogger(__name__)

### Alert Triggering for Critical Issues ###


def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """Triggers an alert for critical failures."""
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        message=message,
        type=AlertType.ALERT_TYPE_DATA_INTEGRITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="cbor_utils",
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {alert.severity}")


### Data Transformation with Senary Encoding ###


def transform_data(value, use_senary=False):
    """
    Transforms data for CBOR encoding/decoding, applying senary encoding when required.

    Args:
        value (any): Data to transform.
        use_senary (bool): Whether to apply senary encoding.

    Returns:
        Transformed data suitable for CBOR processing.
    """
    if isinstance(value, bytes):
        return encode_to_senary(value) if use_senary else value
    elif isinstance(value, dict):
        return {k: transform_data(v, use_senary) for k, v in value.items()}
    elif isinstance(value, list):
        return [transform_data(v, use_senary) for v in value]
    elif isinstance(value, str):
        return decode_from_senary(value) if use_senary and is_senary(value) else value
    elif isinstance(value, (int, float, bool)) or value is None:
        return value
    else:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_unsupported_type",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="CBOR Encoding",
            message=f"Unsupported data type: {type(value).__name__}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE,
        )
        logger.error(f"Unsupported type in CBOR transform: {error_log.message}")
        raise TypeError(error_log.message)  # Raise directly for unsupported type


### CBOR Encoding ###


def encode_data(data, use_senary=False):
    """
    Encodes data to CBOR format and returns it as EncryptedData protobuf object.

    Args:
        data (any): Data to encode.
        use_senary (bool): Whether to apply senary encoding.

    Returns:
        EncryptedData: CBOR-encoded data wrapped in EncryptedData protobuf.
    """
    try:
        transformed_data = transform_data(data, use_senary=use_senary)
        encoded = cbor2.dumps(transformed_data)
        logger.debug("Data encoded to CBOR format")
        return EncryptedData(ciphertext=encoded)
    except TypeError as e:
        # Pass TypeError up directly to ensure test compatibility
        raise e
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_cbor_encoding_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="CBOR Encoding",
            message="CBOR encoding failed.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert(
            "CBOR encoding critical failure", AlertSeverity.ALERT_SEVERITY_CRITICAL
        )
        raise ValueError("CBOR encoding error occurred") from e


### CBOR Decoding ###


def decode_data(encrypted_data, use_senary=False):
    """
    Decodes CBOR data from an EncryptedData protobuf object.

    Args:
        encrypted_data (EncryptedData): EncryptedData protobuf with CBOR content.
        use_senary (bool): Whether to apply senary encoding during transformation.

    Returns:
        Decoded data in original format.
    """
    try:
        decoded = cbor2.loads(encrypted_data.ciphertext)
        logger.debug("CBOR data successfully decoded")
        return transform_data(decoded, use_senary=use_senary)
    except cbor2.CBORDecodeError as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_cbor_decode_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="CBOR Decoding",
            message="CBOR decoding failed due to invalid format.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert(
            "CBOR decoding critical failure", AlertSeverity.ALERT_SEVERITY_CRITICAL
        )
        raise ValueError(
            "CBOR decode error"
        ) from e  # Updated message to match test expectation


### File Operations for CBOR Data ###


def save_to_file(data, file_path, use_senary=False):
    """
    Saves data to a file in CBOR format.

    Args:
        data (any): Data to save.
        file_path (str): Path where the data should be saved.
        use_senary (bool): Whether to apply senary encoding.
    """
    encoded_data = encode_data(data, use_senary=use_senary)
    with open(file_path, "wb") as file:
        file.write(encoded_data.ciphertext)
    logger.info(f"Data saved to file {file_path} with CBOR encoding")


def load_from_file(file_path, use_senary=False):
    """
    Loads CBOR data from a file and decodes it.

    Args:
        file_path (str): Path of the file to load.
        use_senary (bool): Whether to apply senary encoding during transformation.

    Returns:
        Decoded data from file.
    """
    try:
        with open(file_path, "rb") as file:
            cbor_data = file.read()
        encrypted_data = EncryptedData(ciphertext=cbor_data)
        logger.info(f"Data loaded from file {file_path} for CBOR decoding")
        return decode_data(encrypted_data, use_senary=use_senary)
    except FileNotFoundError:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_file_not_found",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="File IO",
            message=f"File not found: {file_path}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE,
        )
        logger.error(f"{error_log.message}")
        _trigger_alert(
            f"File {file_path} not found for CBOR loading",
            AlertSeverity.ALERT_SEVERITY_MEDIUM,
        )
        raise
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_file_load_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="File IO",
            message=f"Error occurred while loading file: {file_path}",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert(
            f"File loading error for {file_path}", AlertSeverity.ALERT_SEVERITY_CRITICAL
        )
        raise
