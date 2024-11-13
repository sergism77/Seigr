import pytest
from src.crypto.cbor_utils import encode_data, decode_data, save_to_file, load_from_file
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData

def test_encode_and_decode_data():
    # Prepare test data with a variety of data types
    test_data = {
        "message": "Hello, Seigr!",
        "count": 42,
        "values": [1, 2, 3, 4, 5],
        "binary_data": b"\x00\x01\x02"
    }
    # Encode data and verify it is in bytes format
    encoded_data = encode_data(test_data)
    assert isinstance(encoded_data.ciphertext, bytes), "Encoded data should be in bytes format."

    # Decode data and verify it matches the original test data
    decoded_data = decode_data(encoded_data)
    assert decoded_data == test_data, "Decoded data should match the original."

def test_save_to_and_load_from_file(tmp_path):
    # Prepare test data to save and reload
    test_data = {
        "name": "Seigr",
        "id": 123,
        "flags": [True, False, True],
        "binary_data": b"\x00\x01\x02"
    }

    # Save to file and load it back, verifying correctness
    file_path = tmp_path / "test_data.cbor"
    save_to_file(test_data, str(file_path))
    loaded_data = load_from_file(str(file_path))
    assert loaded_data == test_data, "Loaded data should match the saved data."

def test_encode_data_with_invalid_types():
    # Attempt to encode data with an invalid type (set), expecting a TypeError
    with pytest.raises(TypeError, match="Unsupported type"):
        encode_data({"invalid_type": set([1, 2, 3])})

def test_decode_invalid_cbor_data():
    # Use a deliberately malformed CBOR byte sequence to ensure it triggers CBORDecodeError
    invalid_encrypted_data = EncryptedData(ciphertext=b"\x9f\x9f\x00")  # Truncated CBOR array
    
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_encrypted_data)