import logging
import uuid
import cbor2
from datetime import datetime, timezone
from typing import Any, Union
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

# Initialize logger
logger = logging.getLogger(__name__)

def encode_data(data: Any, use_senary: bool = False, transaction_id: str = None) -> EncryptedData:
    """Encodes data into CBOR format, encapsulated in EncryptedData with optional senary encoding."""
    transaction_id = transaction_id or str(uuid.uuid4())  # Generate a unique transaction ID if not provided

    def transform_data(value):
        if isinstance(value, bytes):
            return encode_to_senary(value) if use_senary else value
        elif isinstance(value, dict):
            return {k: transform_data(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [transform_data(v) for v in value]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            return value
        else:
            error_log = ErrorLogEntry(
                error_id="unsupported_type",
                severity=ErrorSeverity.ERROR_SEVERITY_LOW,
                component="CBOR Encoding",
                message=f"Unsupported type encountered during CBOR encoding: {type(value).__name__}",
                details=f"Value: {repr(value)}",
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
            )
            logger.error(error_log.message)
            raise TypeError(error_log.message)

    transformed_data = transform_data(data)
    try:
        encoded = cbor2.dumps(transformed_data)
        logger.debug("Data encoded to CBOR format with senary encoding: %s", use_senary)
        return EncryptedData(
            ciphertext=encoded,
            metadata={
                "senary_encoding": str(use_senary),
                "format": "CBOR",
                "transaction_id": transaction_id,
                "encoding_timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="cbor_encoding_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="CBOR Encoding",
            message="Failed to encode data to CBOR format.",
            details=f"Error: {str(e)}, Data ID: {transaction_id}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError(error_log.message) from e

def decode_data(encrypted_data: EncryptedData, use_senary: bool = False, transaction_id: str = None) -> Union[dict, list]:
    """Decodes CBOR data from EncryptedData, optionally decoding senary strings back to binary."""
    transaction_id = transaction_id or str(uuid.uuid4())

    def transform_data(value):
        if isinstance(value, str) and use_senary and is_senary(value):
            try:
                return decode_from_senary(value)
            except ValueError:
                error_log = ErrorLogEntry(
                    error_id="senary_decode_fail",
                    severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                    component="CBOR Decoding",
                    message="Invalid senary encoding encountered during CBOR decoding.",
                    details=f"Failed value: {value}, Transaction ID: {transaction_id}",
                    resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
                )
                logger.error(error_log.message)
                raise ValueError("Invalid senary encoding")
        elif isinstance(value, dict):
            return {k: transform_data(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [transform_data(v) for v in value]
        return value

    try:
        decoded = cbor2.loads(encrypted_data.ciphertext)
        transformed_data = transform_data(decoded)
        logger.debug("Data decoded from CBOR with senary decoding: %s", use_senary)
        return transformed_data
    except cbor2.CBORDecodeError as e:
        error_log = ErrorLogEntry(
            error_id="cbor_decode_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="CBOR Decoding",
            message="CBOR decode error occurred.",
            details=f"Error: {str(e)}, Transaction ID: {transaction_id}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError("CBOR decode error") from e
    except ValueError as e:
        error_log = ErrorLogEntry(
            error_id="senary_decode_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="CBOR Decoding",
            message="Invalid senary encoding during CBOR decode.",
            details=f"Error: {str(e)}, Transaction ID: {transaction_id}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError("Invalid senary encoding") from e
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="decode_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="CBOR Decoding",
            message="Unexpected error during CBOR decoding.",
            details=f"Error: {str(e)}, Transaction ID: {transaction_id}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError("Decoding error") from e

def save_to_file(data: Any, file_path: str, use_senary: bool = False) -> None:
    """Encodes data to CBOR and saves it to a file."""
    encoded_data = encode_data(data, use_senary=use_senary)
    with open(file_path, 'wb') as file:
        file.write(encoded_data.ciphertext)
    logger.info(f"Data saved to file {file_path}")

def load_from_file(file_path: str, use_senary: bool = False) -> Union[dict, list]:
    """Loads CBOR-encoded data from a file and decodes it."""
    with open(file_path, 'rb') as file:
        cbor_data = file.read()
    encrypted_data = EncryptedData(ciphertext=cbor_data)
    return decode_data(encrypted_data, use_senary=use_senary)
