import pytest
import os
from src.crypto.cbor_utils import encode_data, decode_data, save_to_file, load_from_file
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData

def test_encode_and_decode_data():
    test_data = {
        "message": "Hello, Seigr!",
        "count": 42,
        "values": [1, 2, 3, 4, 5],
        "binary_data": b"\x00\x01\x02"
    }
    
    encoded_data = encode_data(test_data, use_senary=False)
    assert isinstance(encoded_data.ciphertext, bytes), "Encoded data should be in bytes format."
    
    decoded_data = decode_data(encoded_data, use_senary=False)
    assert decoded_data == test_data, "Decoded data should match the original."

def test_save_to_and_load_from_file(tmp_path):
    test_data = {
        "name": "Seigr",
        "id": 123,
        "flags": [True, False, True],
        "binary_data": b"\x00\x01\x02"
    }
    
    file_path = tmp_path / "test_data.cbor"
    save_to_file(test_data, str(file_path), use_senary=True)
    loaded_data = load_from_file(str(file_path), use_senary=True)
    assert loaded_data["binary_data"] == test_data["binary_data"], "Binary data should match the original."

def test_encode_data_with_invalid_types():
    with pytest.raises(TypeError, match="Unsupported type"):
        encode_data({"invalid_type": set([1, 2, 3])}, use_senary=False)

def test_decode_invalid_cbor_data():
    # Wrap invalid data in an EncryptedData message as expected by decode_data
    invalid_encrypted_data = EncryptedData(ciphertext=b"Not a valid CBOR byte sequence")
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_encrypted_data, use_senary=False)

def test_invalid_senary_encoding():
    invalid_senary_data = {"binary_data": "Invalid#Senary!Data"}  # Non-senary string for testing
    encoded_invalid = encode_data(invalid_senary_data, use_senary=False)
    with pytest.raises(ValueError, match="Invalid senary encoding"):
        decode_data(encoded_invalid, use_senary=True)
