import pytest
from cryptography.exceptions import InvalidSignature
from src.crypto.asymmetric_utils import (
    generate_key_pair,
    sign_data,
    verify_signature,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key
)
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry

def test_generate_key_pair():
    key_pair = generate_key_pair()
    assert isinstance(key_pair.public_key, bytes), "Public key should be in bytes format."
    assert isinstance(key_pair.private_key, bytes), "Private key should be in bytes format."
    assert len(key_pair.public_key) > 0, "Public key should not be empty."
    assert len(key_pair.private_key) > 0, "Private key should not be empty."

def test_sign_and_verify_signature():
    data = b"Sample data for signing"
    key_pair = generate_key_pair()

    # Sign data and validate SignatureLog structure
    signature_log = sign_data(data, key_pair.private_key)
    assert hasattr(signature_log, 'signature'), "SignatureLog should contain a 'signature' field."
    assert isinstance(signature_log.signature, bytes), "Signature should be in bytes format."
    assert len(signature_log.signature) > 0, "Signature should not be empty."

    # Verify signature
    is_valid = verify_signature(data, signature_log.signature, key_pair.public_key)
    assert is_valid, "Signature verification should pass with correct data and keys."

    # Test with tampered data
    tampered_data = b"Tampered data"
    is_valid_tampered = verify_signature(tampered_data, signature_log.signature, key_pair.public_key)
    assert not is_valid_tampered, "Signature verification should fail with tampered data."

def test_serialize_and_load_public_key():
    key_pair = generate_key_pair()
    public_key = load_public_key(key_pair.public_key)

    serialized_public_key = serialize_public_key(public_key)
    reloaded_public_key = load_public_key(serialized_public_key)

    assert serialized_public_key == key_pair.public_key, "Serialized public key should match the original."
    assert reloaded_public_key.public_numbers() == public_key.public_numbers(), "Reloaded public key should match."

def test_serialize_and_load_private_key():
    key_pair = generate_key_pair()
    private_key = load_private_key(key_pair.private_key)

    serialized_private_key = serialize_private_key(private_key)
    reloaded_private_key = load_private_key(serialized_private_key)

    assert serialized_private_key == key_pair.private_key, "Serialized private key should match the original."
    assert reloaded_private_key.private_numbers() == private_key.private_numbers(), "Reloaded private key should match."

def test_invalid_signature_verification():
    data = b"Sample data for signing"
    key_pair = generate_key_pair()

    signature_log = sign_data(data, key_pair.private_key)

    alt_key_pair = generate_key_pair()
    is_valid = verify_signature(data, signature_log.signature, alt_key_pair.public_key)
    assert not is_valid, "Verification should fail with a different public key."

def test_invalid_key_loading():
    invalid_pem = b"Invalid key data"
    
    # Test loading an invalid public key
    with pytest.raises(ValueError) as excinfo:
        load_public_key(invalid_pem)
    assert "Unable to load PEM" in str(excinfo.value), "Expected a ValueError indicating public key loading failure."

    # Test loading an invalid private key
    with pytest.raises(ValueError) as excinfo:
        load_private_key(invalid_pem)
    assert "Could not deserialize key data" in str(excinfo.value), "Expected a ValueError indicating private key loading failure."

def test_sign_data_with_invalid_key():
    invalid_private_key = b"Invalid private key data"
    data = b"Data to sign"
    with pytest.raises(ValueError) as excinfo:
        sign_data(data, invalid_private_key)
    assert "Could not deserialize key data" in str(excinfo.value), "Expected a ValueError for invalid private key signing."

def test_verify_signature_with_invalid_signature():
    data = b"Sample data"
    key_pair = generate_key_pair()
    signature_log = sign_data(data, key_pair.private_key)

    # Test with an altered signature
    invalid_signature = signature_log.signature[:-1] + b"0"
    is_valid = verify_signature(data, invalid_signature, key_pair.public_key)
    assert not is_valid, "Verification should fail with an invalid signature."
