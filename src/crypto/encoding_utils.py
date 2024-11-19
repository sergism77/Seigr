import logging
from datetime import datetime, timezone
from src.crypto.key_derivation import derive_key_from_password
from src.crypto.symmetric_utils import encrypt_data, decrypt_data
from src.crypto.secure_logging import log_secure_action
from src.crypto.helpers import encode_to_senary, decode_from_senary, generate_metadata
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION

logger = logging.getLogger(__name__)

REQUIRED_METADATA_LENGTH = 6  # Set according to Seigr protocol requirements


def encode_seigr_section(
    section_data: bytes, section_type: str, password: str = None
) -> str:
    """Encodes a section of a .seigr file with senary encoding and optional encryption."""
    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Encoding start", {"section_type": section_type}
    )

    if password:
        key = derive_key_from_password(password)
        section_data = encrypt_data(section_data, key)
        log_secure_action(
            f"{SEIGR_CELL_ID_PREFIX} Data section encrypted",
            {"section_type": section_type},
        )

    senary_encoded = encode_to_senary(section_data)
    section_hash = _calculate_hash(section_data)
    metadata = _generate_section_metadata(section_type, section_hash)

    full_encoded_section = f"{metadata}{senary_encoded}"
    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Encoding complete",
        {"section_type": section_type, "section_hash": section_hash},
    )
    return full_encoded_section


def decode_seigr_section(
    encoded_section: str, section_type: str, password: str = None
) -> bytes:
    """Decodes a senary-encoded section of a .seigr file with integrity checks and optional decryption."""
    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Decoding start", {"section_type": section_type}
    )

    metadata, senary_data = encoded_section[:12], encoded_section[12:]
    expected_hash = metadata[-REQUIRED_METADATA_LENGTH:]

    binary_data = decode_from_senary(senary_data)
    actual_hash = _calculate_hash(binary_data)

    if actual_hash != expected_hash:
        log_secure_action(
            f"{SEIGR_CELL_ID_PREFIX} Integrity check failed",
            {"section_type": section_type},
        )
        raise ValueError("Data integrity check failed")
    else:
        log_secure_action(
            f"{SEIGR_CELL_ID_PREFIX} Integrity check passed",
            {"section_type": section_type},
        )

    if password:
        key = derive_key_from_password(password)
        binary_data = decrypt_data(binary_data, key)
        log_secure_action(
            f"{SEIGR_CELL_ID_PREFIX} Data section decrypted",
            {"section_type": section_type},
        )

    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Decoding complete", {"section_type": section_type}
    )
    return binary_data


def _calculate_hash(data: bytes) -> str:
    """Calculates a hash for integrity check."""
    import hashlib

    hash_obj = hashlib.sha256(data)
    return hash_obj.hexdigest()[:REQUIRED_METADATA_LENGTH]


def _encode_senary_cell(byte: int) -> str:
    """Encodes a byte into a senary cell with redundancy and metadata."""
    base6_digits = _to_base6(byte).zfill(3)
    redundancy = _calculate_redundancy(byte)
    metadata = _generate_metadata()
    senary_cell = f"{base6_digits}{redundancy}{metadata}"
    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Encoded senary cell",
        {"byte": byte, "senary_cell": senary_cell},
    )
    return senary_cell


def _decode_senary_cell(senary_cell: str) -> int:
    """Decodes a senary cell back to a byte, verifying redundancy."""
    base6_digits = senary_cell[:3]
    redundancy = senary_cell[3:4]
    metadata = senary_cell[4:6]  # Reserved for future enhancements
    byte = _from_base6(base6_digits)

    if not _verify_redundancy(byte, redundancy):
        log_secure_action(
            f"{SEIGR_CELL_ID_PREFIX} Redundancy check failed",
            {"senary_cell": senary_cell},
        )
        raise ValueError("Redundancy check failed for cell")

    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Decoded senary cell",
        {"senary_cell": senary_cell, "byte": byte},
    )
    return byte


def _generate_section_metadata(section_type: str, section_hash: str) -> str:
    """Generates metadata based on section type and hash for section integrity tracking."""
    type_code = section_type[:2].upper()
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
    metadata = f"{SEIGR_CELL_ID_PREFIX}_{type_code}{timestamp}{SEIGR_VERSION[:2]}{section_hash[:REQUIRED_METADATA_LENGTH]}"
    log_secure_action(
        f"{SEIGR_CELL_ID_PREFIX} Generated section metadata", {"metadata": metadata}
    )
    return metadata


def _to_base6(num: int) -> str:
    """Converts an integer to a base-6 (senary) string."""
    if num == 0:
        return "0"
    base6 = ""
    while num:
        base6 = str(num % 6) + base6
        num //= 6
    return base6


def _from_base6(base6_str: str) -> int:
    """Converts a base-6 (senary) string back to an integer."""
    num = 0
    for char in base6_str:
        num = num * 6 + int(char)
    return num


def _calculate_redundancy(byte: int) -> str:
    """Generates a redundancy marker for error-checking, based on the byte's parity."""
    return "0" if byte % 2 == 0 else "1"


def _verify_redundancy(byte: int, redundancy: str) -> bool:
    """Verifies the redundancy marker to check the byte's integrity."""
    expected_redundancy = _calculate_redundancy(byte)
    return expected_redundancy == redundancy


def _generate_metadata() -> str:
    """Generates a two-digit metadata string, which could include a simple timestamp."""
    timestamp = datetime.now(timezone.utc).second % 100
    return str(timestamp).zfill(2)
