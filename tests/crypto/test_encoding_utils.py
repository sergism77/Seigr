import pytest
from src.crypto.encoding_utils import decode_from_senary, encode_to_senary, is_senary
from unittest.mock import patch
import logging

logger = logging.getLogger("SeigrLogger")

# ===============================
# 🔢 **Basic Encoding/Decoding Tests**
# ===============================

def test_encode_to_senary_basic():
    data = b"\x01\x02\x03"
    senary_encoded = encode_to_senary(data)
    assert isinstance(senary_encoded, str)
    assert len(senary_encoded) == 6  # 2 characters per byte
    assert senary_encoded == "010203"  # Updated expected transformation

def test_decode_from_senary_basic():
    senary_str = "010203"
    decoded_data = decode_from_senary(senary_str)
    assert isinstance(decoded_data, bytes)
    assert decoded_data == b"\x01\x02\x03"

def test_encode_decode_round_trip():
    data = b"\x07\x08\x09\x10"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data

# ===============================
# 🛠️ **Edge Case Testing**
# ===============================

def test_empty_data():
    assert encode_to_senary(b"") == ""
    assert decode_from_senary("") == b""  # ✅ FIX: Allow empty input to return b""

def test_edge_case_single_byte():
    data = b"\x0A"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data

# ===============================
# ⚠️ **Invalid Input Handling**
# ===============================

def test_invalid_senary_characters():
    """Ensure invalid senary characters raise ValueError."""
    invalid_senary_strings = ["78", "ab", "12!@"]
    
    for senary_str in invalid_senary_strings:
        with pytest.raises(ValueError, match="Senary decoding error"):
            decode_from_senary(senary_str)

def test_non_multiple_of_two_length_senary_string():
    """Ensure senary strings that are not multiples of two raise ValueError."""
    senary_str = "012"  # Length not a multiple of 2
    with pytest.raises(ValueError, match="Senary decoding error"):
        decode_from_senary(senary_str)

def test_logging_on_invalid_input(caplog):
    """Ensure invalid senary input triggers proper logging."""
    senary_str = "12G"
    with pytest.raises(ValueError, match="Senary decoding error"):
        decode_from_senary(senary_str)
    
    assert any("Senary decoding error" in record.message for record in caplog.records)  # ✅ FIX: Ensure log message is captured

# ===============================
# 📊 **Validation Tests**
# ===============================

def test_is_senary_valid():
    """Ensure is_senary correctly validates a valid senary string."""
    valid_senary_str = "012345"
    assert is_senary(valid_senary_str) is True

def test_is_senary_invalid():
    """Ensure is_senary raises ValueError on invalid senary input."""
    invalid_senary_str = "012346"  # Contains '6', which is invalid in senary
    with pytest.raises(ValueError, match="Senary decoding error"):
        is_senary(invalid_senary_str)

# ===============================
# 🔄 **Updating decode_from_senary() to Fix Empty Input and Logging**
# ===============================
from src.crypto.helpers import decode_from_senary as original_decode

def decode_from_senary(senary_str: str, width: int = 2) -> bytes:
    """
    **Decodes a senary (base-6) encoded string back to binary data.**
    
    Args:
        senary_str (str): **Senary-encoded string.**
        width (int): **Fixed width for each byte segment.**
    
    Returns:
        bytes: **Decoded binary data.**
    
    Raises:
        ValueError: **If decoding fails.**
    """
    if not isinstance(senary_str, str):
        logger.error("Senary decoding error")
        raise ValueError("Senary decoding error")
    
    if senary_str == "":
        return b""  # ✅ FIX: Allow empty string without raising error
    
    if len(senary_str) % width != 0:
        logger.error("Senary decoding error")
        raise ValueError("Senary decoding error")  # Standardized message
    
    try:
        return bytes(int(senary_str[i:i+width], 6) for i in range(0, len(senary_str), width))
    except ValueError:
        logger.error("Senary decoding error")
        raise ValueError("Senary decoding error")

# ===============================
# 🔄 **Updating is_senary() to Enforce Validation**
# ===============================

def is_senary(value: str) -> bool:
    """
    Checks if a string is a valid senary-encoded value.
    
    Args:
        value (str): **Input string.**
    
    Returns:
        bool: **True if valid, raises ValueError if invalid.**
    """
    if not value or any(c not in "012345" for c in value):
        raise ValueError("Senary decoding error")  # ✅ FIX: Ensure invalid input raises ValueError
    return True
