# tests/crypto/test_asymmetric_utils.py

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from src.crypto.asymmetric_utils import (
    generate_key_pair,
    sign_data,
    verify_signature,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key
)


def test_generate_key_pair():
    # Generate the key pair and assert both keys are returned as bytes and are non-empty
    public_key_pem, private_key_pem = generate_key_pair()
    assert isinstance(public_key_pem, bytes), "Public key should be in bytes format."
    assert isinstance(private_key_pem, bytes), "Private key should be in bytes format."
    assert len(public_key_pem) > 0, "Public key should not be empty."
    assert len(private_key_pem) > 0, "Private key should not be empty."


def test_sign_and_verify_signature():
    # Generate keys and sign some data
    data = b"Sample data for signing"
    public_key_pem, private_key_pem = generate_key_pair()

    # Sign data with the private key
    signature = sign_data(data, private_key_pem)
    assert isinstance(signature, bytes), "Signature should be in bytes format."
    assert len(signature) > 0, "Signature should not be empty."

    # Verify signature with the correct public key
    is_valid = verify_signature(data, signature, public_key_pem)
    assert is_valid, "Signature verification should pass with correct data and keys."

    # Attempt verification with modified data (should fail)
    tampered_data = b"Tampered data"
    is_valid_tampered = verify_signature(tampered_data, signature, public_key_pem)
    assert not is_valid_tampered, "Signature verification should fail with tampered data."


def test_serialize_and_load_public_key():
    # Generate a key pair and serialize the public key
    public_key_pem, private_key_pem = generate_key_pair()
    public_key = load_public_key(public_key_pem)

    # Serialize and reload the public key
    serialized_public_key = serialize_public_key(public_key)
    reloaded_public_key = load_public_key(serialized_public_key)

    # Confirm serialized and reloaded public keys are the same
    assert serialized_public_key == public_key_pem, "Serialized public key should match the original."
    assert reloaded_public_key.public_numbers() == public_key.public_numbers(), "Reloaded public key should match."


def test_serialize_and_load_private_key():
    # Generate a key pair and serialize the private key
    public_key_pem, private_key_pem = generate_key_pair()
    private_key = load_private_key(private_key_pem)

    # Serialize and reload the private key
    serialized_private_key = serialize_private_key(private_key)
    reloaded_private_key = load_private_key(serialized_private_key)

    # Confirm serialized and reloaded private keys are the same
    assert serialized_private_key == private_key_pem, "Serialized private key should match the original."
    assert reloaded_private_key.private_numbers() == private_key.private_numbers(), "Reloaded private key should match."


def test_invalid_signature_verification():
    # Generate keys and sign some data
    data = b"Sample data for signing"
    public_key_pem, private_key_pem = generate_key_pair()

    # Sign data with the private key
    signature = sign_data(data, private_key_pem)

    # Attempt verification with a different public key (should fail)
    alt_public_key_pem, _ = generate_key_pair()
    is_valid = verify_signature(data, signature, alt_public_key_pem)
    assert not is_valid, "Verification should fail with a different public key."
