"""
📊 **Test Suite for Encoding Utilities**
Ensures correctness of **Senary encoding/decoding** and **hash encoding verification**.
Covers **edge cases, invalid inputs, and round-trip integrity**.
"""

import pytest

from src.crypto.encoding_utils import decode_from_senary, encode_to_senary, is_senary

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
    assert decode_from_senary("") == b""


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
        with pytest.raises(ValueError, match="Senary decoding error"):  # ✅ FIX: Match correct error message
            decode_from_senary(senary_str)


def test_non_multiple_of_two_length_senary_string():
    """Ensure senary strings that are not multiples of two raise ValueError."""
    senary_str = "012"  # Length not a multiple of 2
    with pytest.raises(ValueError, match="Invalid senary length"):  # ✅ FIX: Enforce correct length error
        decode_from_senary(senary_str)


def test_logging_on_invalid_input(caplog):
    """Ensure invalid senary input triggers proper logging."""
    senary_str = "12G"
    with pytest.raises(ValueError, match="Senary decoding error"):  # ✅ FIX: Match correct error message
        decode_from_senary(senary_str)
    assert any("Senary decoding error" in record.message for record in caplog.records)


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
    with pytest.raises(ValueError, match="Senary validation failed"):
        is_senary(invalid_senary_str)
