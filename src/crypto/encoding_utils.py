import logging
import uuid
from datetime import datetime, timezone
from typing import Union
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData, EncryptionType
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

logger = logging.getLogger(__name__)

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string without additional transformations."""
    senary_str = ""
    for byte in binary_data:
        try:
            encoded_byte = _base6_encode(byte).zfill(2)  # Ensure 2 characters per byte for consistency
            senary_str += encoded_byte
        except ValueError as e:
            error_log = ErrorLogEntry(
                error_id="senary_encode_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                component="Encoding Utilities",
                message="Failed to encode byte to senary format.",
                details=f"Byte: {byte}, Error: {str(e)}",
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message) from e
    logger.debug(f"Successfully encoded data to senary format: {senary_str}")
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    if not is_senary(senary_str):
        error_log = ErrorLogEntry(
            error_id="senary_validation_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="Encoding Utilities",
            message="Invalid senary encoding: Senary string must contain only '0'-'5' and have an even length.",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(error_log.message)
        raise ValueError(error_log.message)
    
    binary_data = bytearray()
    for i in range(0, len(senary_str), 2):
        encoded_pair = senary_str[i:i + 2]
        try:
            byte = _base6_decode(encoded_pair)
            binary_data.append(byte)
        except ValueError as e:
            error_log = ErrorLogEntry(
                error_id="senary_decode_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                component="Encoding Utilities",
                message="Failed to decode senary-encoded pair back to binary.",
                details=f"Encoded pair: {encoded_pair}, Error: {str(e)}",
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message) from e
    logger.debug("Successfully decoded senary data back to binary format.")
    return bytes(binary_data)

def is_senary(senary_str: str) -> bool:
    """Checks if a string is a valid senary-encoded string, logging validation errors."""
    is_valid = len(senary_str) % 2 == 0 and all(char in '012345' for char in senary_str)
    if not is_valid:
        error_log = ErrorLogEntry(
            error_id="senary_string_invalid",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="Encoding Utilities",
            message=f"Senary validation failed for string: {senary_str}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.warning(f"{error_log.message}")
    return is_valid

### Helper functions for base-6 encoding and decoding ###

def _base6_encode(byte: int) -> str:
    """Converts a single byte to a senary (base-6) encoded string with fixed width."""
    if byte < 0 or byte > 255:
        error_log = ErrorLogEntry(
            error_id="byte_range_error",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="Encoding Utilities",
            message="Input byte must be in range 0-255 for base-6 encoding.",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(error_log.message)
        raise ValueError(error_log.message)
    
    senary_digits = []
    for _ in range(2):  # Two base-6 digits to fully cover a byte's range
        senary_digits.append(str(byte % 6))
        byte //= 6
    encoded = ''.join(reversed(senary_digits))
    logger.debug(f"Base-6 encoded byte: {encoded}")
    return encoded

def _base6_decode(senary_str: str) -> int:
    """Converts a senary (base-6) encoded string back to a byte."""
    if not all(char in '012345' for char in senary_str):
        error_log = ErrorLogEntry(
            error_id="senary_char_error",
            severity=ErrorSeverity.ERROR_SEVERITY_LOW,
            component="Encoding Utilities",
            message="Senary string contains invalid characters for base-6 decoding.",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(error_log.message)
        raise ValueError(error_log.message)
    
    byte = 0
    for char in senary_str:
        byte = byte * 6 + int(char)
    logger.debug(f"Base-6 decoded byte: {byte}")
    return byte

def package_encrypted_data(ciphertext: bytes, iv: bytes, encryption_type: EncryptionType, key_id: str, metadata: dict) -> EncryptedData:
    """Packages encrypted data along with encryption metadata in the protocol-defined EncryptedData format."""
    enriched_metadata = {**metadata, "transaction_id": str(uuid.uuid4()), "encoding_context": "senary"}
    
    encrypted_data = EncryptedData(
        ciphertext=ciphertext,
        iv=iv,
        encryption_type=encryption_type,
        key_id=key_id,
        metadata=enriched_metadata,
        encryption_timestamp=datetime.now(timezone.utc).isoformat() + "Z"
    )
    logger.debug(f"Packaged encrypted data in EncryptedData format with metadata: {enriched_metadata}")
    return encrypted_data
