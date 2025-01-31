"""
📌 **Seigr CBOR Utilities Module**
Provides functionality for CBOR encoding, decoding, transformation, and secure file handling.
Fully aligned with **Seigr cryptographic protocols and logging standards**.
"""

import uuid
from datetime import datetime, timezone

import cbor2

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import decode_from_senary, encode_to_senary, is_senary
from src.crypto.alert_utils import trigger_alert
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.logger.secure_logger import secure_logger


# ===============================
# 🔄 **Data Transformation**
# ===============================
def transform_data(value, use_senary: bool = False):
    """
    **Transforms data for CBOR encoding/decoding.**

    Args:
        value: The data to transform.
        use_senary (bool, optional): Whether to apply Senary transformation (default: False).

    Returns:
        Transformed data suitable for CBOR encoding.

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

    trigger_alert(
        message=f"Unsupported data type: {type(value).__name__}",
        severity=AlertSeverity.ALERT_SEVERITY_WARNING,
        alert_type=AlertType.ALERT_TYPE_DATA_VALIDATION,  # ✅ Properly classified
        source_component="cbor_utils",
    )

    raise TypeError(f"Unsupported data type: {type(value).__name__}")


# ===============================
# 📝 **CBOR Encoding**
# ===============================
def encode_data(data, use_senary: bool = False) -> EncryptedData:
    """
    **Encodes data into CBOR format with optional Senary transformation.**

    Args:
        data: The data to encode.
        use_senary (bool, optional): Whether to use Senary encoding (default: False).

    Returns:
        EncryptedData: The CBOR-encoded data wrapped in a Protobuf structure.

    Raises:
        ValueError: If encoding fails.
    """
    try:
        encoded = cbor2.dumps(transform_data(data, use_senary=use_senary))
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="CBOR Encoding",
            message="✅ Data successfully encoded to CBOR format.",
            sensitive=False,
            use_senary=use_senary,
        )
        return EncryptedData(ciphertext=encoded)
    except Exception as e:
        trigger_alert(
            message=f"❌ CBOR encoding error: {str(e)}",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_SECURITY,  # ✅ Correct Alert Type
            source_component="cbor_utils",
        )

        raise ValueError("CBOR encoding error occurred") from e


# ===============================
# 🔓 **CBOR Decoding**
# ===============================
def decode_data(encrypted_data: EncryptedData, use_senary: bool = False):
    """
    **Decodes CBOR-encoded data from an EncryptedData protobuf structure.**

    Args:
        encrypted_data (EncryptedData): The Protobuf-wrapped encrypted CBOR data.
        use_senary (bool, optional): Whether to apply Senary decoding (default: False).

    Returns:
        Decoded data.

    Raises:
        ValueError: If decoding fails.
    """
    if not encrypted_data or not encrypted_data.ciphertext:
        trigger_alert(
            message="❌ Invalid EncryptedData object for decoding",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_DATA_VALIDATION,  # ✅ Correct classification
            source_component="cbor_utils",
        )

        raise ValueError("Invalid EncryptedData object for decoding")

    try:
        decoded = cbor2.loads(encrypted_data.ciphertext)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="CBOR Decoding",
            message="✅ Data successfully decoded from CBOR format.",
            sensitive=False,
            use_senary=use_senary,
        )
        return decoded
    except cbor2.CBORDecodeError as e:
        trigger_alert(
            message=f"❌ CBOR decode error: {str(e)}",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_SECURITY,  # ✅ Proper Alert Type
            source_component="cbor_utils",
        )

        raise ValueError("CBOR decode error") from e
    except Exception as e:
        trigger_alert(
            message=f"❌ CBOR decoding exception: {str(e)}",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_SECURITY,  # ✅ Correct Type
            source_component="cbor_utils",
        )

        raise ValueError("CBOR decoding failed") from e


# ===============================
# 💾 **Save to File**
# ===============================
def save_to_file(data, file_path: str, use_senary: bool = False):
    """
    **Saves encoded CBOR data to a file.**

    Args:
        data: The data to save.
        file_path (str): Path to the output file.
        use_senary (bool, optional): Whether to use Senary encoding (default: False).

    Raises:
        IOError: If file saving fails.
    """
    try:
        encoded_data = encode_data(data, use_senary=use_senary)
        with open(file_path, "wb") as file:
            file.write(encoded_data.ciphertext)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="FileIO",
            message=f"✅ Data successfully saved to file: {file_path}",
            sensitive=False,
            use_senary=use_senary,
        )
    except Exception as e:
        trigger_alert(
            message=f"❌ Failed to save data to file: {file_path}. Error: {str(e)}",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_FILE_IO,  # ✅ Correct Alert Type
            source_component="cbor_utils",
        )

        raise IOError("Failed to save file") from e


# ===============================
# 📂 **Load from File**
# ===============================
def load_from_file(file_path: str):
    """
    **Loads CBOR-encoded data from a file.**

    Args:
        file_path (str): Path to the file.

    Returns:
        Decoded data.

    Raises:
        IOError: If file loading fails.
    """
    try:
        with open(file_path, "rb") as file:
            encrypted_data = EncryptedData(ciphertext=file.read())
        decoded_data = decode_data(encrypted_data)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="FileIO",
            message=f"✅ Data successfully loaded from file: {file_path}",
            sensitive=False,
            use_senary=False,
        )
        return decoded_data
    except Exception as e:
        trigger_alert(
            message=f"❌ Failed to load data from file: {file_path}. Error: {str(e)}",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_FILE_IO,  # ✅ Correct Alert Type
            source_component="cbor_utils",
        )

        raise IOError("Failed to load file") from e
