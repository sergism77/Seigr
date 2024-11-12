# tests/crypto/test_encoding_utils.py

import pytest
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary

def test_encode_to_senary_basic():
    # Test encoding a simple byte sequence
    data = b"\x01\x02\x03"
    senary_encoded = encode_to_senary(data)
    assert isinstance(senary_encoded, str)
    assert len(senary_encoded) == 6  # 2 characters per byte
    assert senary_encoded == "012034"  # Expected output may differ depending on transformations

def test_decode_from_senary_basic():
    # Test decoding a simple senary string back to bytes
    senary_str = "012034"
    decoded_data = decode_from_senary(senary_str)
    assert isinstance(decoded_data, bytes)
    assert decoded_data == b"\x01\x02\x03"  # Expected output may vary

def test_encode_decode_round_trip():
    # Ensure encoding and decoding are reversible
    data = b"\x07\x08\x09\x10"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data  # Round-trip should yield original data

def test_empty_data():
    # Encoding and decoding empty data should yield empty results
    assert encode_to_senary(b"") == ""
    assert decode_from_senary("") == b""

def test_edge_case_single_byte():
    # Test encoding and decoding a single byte
    data = b"\x0A"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data

def test_non_even_length_senary_string():
    # Test that decoding an odd-length senary string raises a ValueError
    senary_str = "012"  # Odd number of characters
    with pytest.raises(ValueError, match="Senary string length must be even"):
        decode_from_senary(senary_str)

def test_invalid_senary_characters():
    # Test decoding of senary strings with invalid characters
    invalid_senary_strings = ["78", "ab", "12!@"]

    for senary_str in invalid_senary_strings:
        with pytest.raises(ValueError, match="Invalid character in senary string"):
            decode_from_senary(senary_str)

def test_complex_data():
    # Test encoding and decoding a more complex byte sequence
    data = b"\xff\xee\xdd\xcc\xbb\xaa"
    senary_encoded = encode_to_senary(data)
    decoded_data = decode_from_senary(senary_encoded)
    assert decoded_data == data  # Round-trip should match original data

def test_logging_on_invalid_input(caplog):
    # Test that invalid senary characters are logged
    senary_str = "12G"
    with pytest.raises(ValueError):
        decode_from_senary(senary_str)
    assert any("Invalid character in senary string" in message for message in caplog.text)

def test_transformed_encoding_consistency():
    # Check the consistency of transformation encoding
    data = b"\x11\x22\x33"
    encoded_data = encode_to_senary(data)
    assert isinstance(encoded_data, str)
    assert len(encoded_data) == 6  # Should be 2 chars per byte after transformations
    assert decode_from_senary(encoded_data) == data  # Consistency check
