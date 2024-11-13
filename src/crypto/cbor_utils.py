import cbor2
import logging
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

logger = logging.getLogger(__name__)

def transform_data(value, use_senary=False):
    if isinstance(value, bytes):
        return encode_to_senary(value) if use_senary else value
    elif isinstance(value, dict):
        return {k: transform_data(v, use_senary) for k, v in value.items()}
    elif isinstance(value, list):
        return [transform_data(v, use_senary) for v in value]
    elif isinstance(value, str):
        # Allow regular strings without senary encoding if `use_senary` is False
        return decode_from_senary(value) if use_senary and is_senary(value) else value
    elif isinstance(value, (int, float, bool)) or value is None:
        return value
    else:
        error_log = ErrorLogEntry(
            error_id="unsupported_type",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="CBOR Encoding",
            message=f"Unsupported type: {type(value).__name__}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(error_log.message)
        raise TypeError(error_log.message)

def encode_data(data, use_senary=False):
    transformed_data = transform_data(data, use_senary=use_senary)
    encoded = cbor2.dumps(transformed_data)
    return EncryptedData(ciphertext=encoded)

def decode_data(encrypted_data, use_senary=False):
    try:
        # Attempting to decode CBOR data
        decoded = cbor2.loads(encrypted_data.ciphertext)
        return transform_data(decoded, use_senary=use_senary)
    except cbor2.CBORDecodeError as e:
        # Log that a decode error occurred
        logger.error("CBOR decode error: Invalid CBOR format detected.")
        error_log = ErrorLogEntry(
            error_id="cbor_decode_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="CBOR Decoding",
            message="CBOR decode error occurred.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError("CBOR decode error occurred") from e
    
def save_to_file(data, file_path, use_senary=False):
    encoded_data = encode_data(data, use_senary=use_senary)
    with open(file_path, 'wb') as file:
        file.write(encoded_data.ciphertext)
    logger.info(f"Data saved to file {file_path}")

def load_from_file(file_path, use_senary=False):
    with open(file_path, 'rb') as file:
        cbor_data = file.read()
    encrypted_data = EncryptedData(ciphertext=cbor_data)
    return decode_data(encrypted_data, use_senary=use_senary)
