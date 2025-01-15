# tests/crypto/test_encoding_utils.py

import pytest

from src.crypto.encoding_utils import decode_from_senary, encode_to_senary, is_senary


def test_encode_to_senary_basic():
    data = b"\x01\x02\x03"
    senary_encoded = encode_to_senary(data)
    assert isinstance(senary_encoded, str)
    assert len(senary_encoded) == 9  # 3 characters per byte now
    # Adjust expected output based on correct transformations
    assert senary_encoded == "001002003"  # Expected value after verification


def test_decode_from_senary_basic():
    senary_str = "001002003"
    decoded_data = decode_from_senary(senary_str)
    assert isinstance(decoded_data, bytes)
    assert decoded_data == b"\x01\x02\x03"


def test_encode_decode_round_trip():
    data = b"\x07\x08\x09\x10"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data


def test_empty_data():
    assert encode_to_senary(b"") == ""
    assert decode_from_senary("") == b""


def test_edge_case_single_byte():
    data = b"\x0A"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data


def test_non_multiple_of_three_length_senary_string():
    # Update this to check for length not multiple of 3
    senary_str = "0123"  # Length not a multiple of 3
    with pytest.raises(ValueError, match="Senary validation failed"):
        decode_from_senary(senary_str)


def test_invalid_senary_characters():
    invalid_senary_strings = ["78", "ab", "12!@"]

    for senary_str in invalid_senary_strings:
        with pytest.raises(ValueError, match="Senary validation failed"):
            decode_from_senary(senary_str)


def test_complex_data():
    data = b"\xff\xee\xdd\xcc\xbb\xaa"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data


def test_logging_on_invalid_input(caplog):
    senary_str = "12G"
    with pytest.raises(ValueError, match="Senary validation failed"):
        decode_from_senary(senary_str)
    assert any("Senary validation failed for string" in record.message for record in caplog.records)


def test_transformed_encoding_consistency():
    data = b"\x11\x22\x33"
    encoded_data = encode_to_senary(data)
    assert isinstance(encoded_data, str)
    assert len(encoded_data) == 9  # Updated for 3 chars per byte
    assert decode_from_senary(encoded_data) == data


def test_is_senary_valid():
    valid_senary_str = "012345012"
    assert is_senary(valid_senary_str) is True


def test_is_senary_invalid():
    invalid_senary_str = "012346"  # Contains '6', which is invalid in senary
    with pytest.raises(ValueError, match="Senary validation failed"):
        is_senary(invalid_senary_str)
