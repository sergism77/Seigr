import unittest
import os
import cbor2
from src.crypto.hypha_crypt import HyphaCrypt, generate_encryption_key, encrypt_data, decrypt_data, derive_encryption_key, generate_salt
from src.dot_seigr.seigr_constants import TRACE_CODE, MAX_TREE_DEPTH
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import OperationLog

class TestHyphaCrypt(unittest.TestCase):
    def setUp(self):
        # Set up test data for each test case
        self.data = b"Test data for HyphaCrypt"
        self.segment_id = "test_segment_id"
        self.hypha_crypt_hex = HyphaCrypt(self.data, self.segment_id, use_senary=False)
        self.hypha_crypt_senary = HyphaCrypt(self.data, self.segment_id, use_senary=True)
        self.password = "secure_password"
        self.salt = generate_salt()
        self.key_from_password = derive_encryption_key(self.password, self.salt)

    def test_initialization(self):
        # Verify initialization with hex and senary modes
        self.assertEqual(self.hypha_crypt_hex.segment_id, self.segment_id)
        self.assertEqual(self.hypha_crypt_senary.segment_id, self.segment_id)
        self.assertFalse(self.hypha_crypt_hex.use_senary)
        self.assertTrue(self.hypha_crypt_senary.use_senary)

    def test_compute_primary_hash_hex(self):
        # Test primary hash in hex mode
        primary_hash_hex = self.hypha_crypt_hex.compute_primary_hash()
        self.assertIsNotNone(primary_hash_hex)
        self.assertTrue(primary_hash_hex.startswith("1:sha256:"))

    def test_compute_primary_hash_senary(self):
        # Test primary hash in senary mode
        primary_hash_senary = self.hypha_crypt_senary.compute_primary_hash()
        self.assertIsNotNone(primary_hash_senary)
        self.assertTrue(all(c in "012345" for c in primary_hash_senary.split(":")[-1]))

    def test_layered_hash_generation(self):
        # Test generation of layered hashes up to MAX_TREE_DEPTH
        hash_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        self.assertEqual(len(hash_tree), MAX_TREE_DEPTH)
        for depth in range(1, MAX_TREE_DEPTH + 1):
            self.assertIn(f"Layer_{depth}", hash_tree)
            self.assertIsInstance(hash_tree[f"Layer_{depth}"], list)

    def test_log_tree_export_cbor(self):
        # Test exporting log tree in CBOR format
        filename_cbor = self.hypha_crypt_hex.export_log_tree(use_cbor=True)
        self.assertTrue(os.path.exists(filename_cbor))
        
        # Load and validate CBOR structure
        with open(filename_cbor, 'rb') as f:
            log_data = cbor2.loads(f.read())
            self.assertIsInstance(log_data, list)
            # Check for valid OperationLog protobuf messages
            for entry in log_data:
                log_entry = OperationLog()
                log_entry.ParseFromString(entry)
                self.assertIn("layer_hash", log_entry.details)

        # Clean up
        os.remove(filename_cbor)

    def test_full_integrity_verification(self):
        # Verify full depth hash tree integrity against itself
        reference_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        result = self.hypha_crypt_hex.verify_integrity(reference_tree=reference_tree)
        self.assertTrue(result)

    def test_partial_integrity_verification(self):
        # Verify partial depth integrity
        reference_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        result = self.hypha_crypt_hex.verify_integrity(reference_tree=reference_tree, partial_depth=MAX_TREE_DEPTH // 2)
        self.assertTrue(result)

    def test_password_derived_encryption_and_decryption(self):
        # Test encryption and decryption using a password-derived key
        encrypted_data = encrypt_data(self.data, self.key_from_password)
        decrypted_data = decrypt_data(encrypted_data, self.key_from_password)
        self.assertEqual(self.data, decrypted_data)

    def test_encryption_and_decryption_with_generated_key(self):
        # Generate random key, encrypt data, then decrypt it
        key = generate_encryption_key()
        encrypted_data = encrypt_data(self.data, key)
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(self.data, decrypted_data)

if __name__ == '__main__':
    unittest.main()
