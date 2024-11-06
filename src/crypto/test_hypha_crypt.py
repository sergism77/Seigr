import unittest
import os
import json
import cbor2
from src.crypto.hypha_crypt import HyphaCrypt, generate_encryption_key, encrypt_data, decrypt_data
from src.dot_seigr.seigr_constants import TRACE_CODE, MAX_TREE_DEPTH

class TestHyphaCrypt(unittest.TestCase):
    def setUp(self):
        # Setup common test data for each test case
        self.data = b"Test data for HyphaCrypt"
        self.segment_id = "test_segment_id"
        self.hypha_crypt_hex = HyphaCrypt(self.data, self.segment_id, use_senary=False)
        self.hypha_crypt_senary = HyphaCrypt(self.data, self.segment_id, use_senary=True)

    def test_initialization(self):
        # Verify that HyphaCrypt initializes correctly with both hex and senary modes
        self.assertEqual(self.hypha_crypt_hex.segment_id, self.segment_id)
        self.assertEqual(self.hypha_crypt_senary.segment_id, self.segment_id)
        self.assertEqual(self.hypha_crypt_hex.use_senary, False)
        self.assertEqual(self.hypha_crypt_senary.use_senary, True)

    def test_compute_primary_hash_hex(self):
        # Test primary hash computation in hexadecimal mode
        primary_hash_hex = self.hypha_crypt_hex.compute_primary_hash()
        self.assertIsNotNone(primary_hash_hex)
        self.assertTrue(primary_hash_hex.startswith("1:sha256:"))  # Assuming default version and algorithm

    def test_compute_primary_hash_senary(self):
        # Test primary hash computation in senary mode
        primary_hash_senary = self.hypha_crypt_senary.compute_primary_hash()
        self.assertIsNotNone(primary_hash_senary)
        self.assertTrue(all(c in "012345" for c in primary_hash_senary.split(":")[-1]))

    def test_layered_hash_generation(self):
        # Test the generation of layered hashes up to MAX_TREE_DEPTH
        hash_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        self.assertEqual(len(hash_tree), MAX_TREE_DEPTH)
        for depth in range(1, MAX_TREE_DEPTH + 1):
            self.assertIn(f"Layer_{depth}", hash_tree)
            self.assertIsInstance(hash_tree[f"Layer_{depth}"], list)

    def test_log_tree_export_json(self):
        # Test exporting the log tree in JSON format
        filename_json = self.hypha_crypt_hex.export_log_tree(use_cbor=False)
        self.assertTrue(os.path.exists(filename_json))
        
        # Load and validate JSON structure
        with open(filename_json, 'r') as f:
            log_data = json.load(f)
            self.assertIsInstance(log_data, list)
            self.assertTrue(all("layer_hash" in entry for entry in log_data))

        # Clean up
        os.remove(filename_json)

    def test_log_tree_export_cbor(self):
        # Test exporting the log tree in CBOR format
        filename_cbor = self.hypha_crypt_hex.export_log_tree(use_cbor=True)
        self.assertTrue(os.path.exists(filename_cbor))
        
        # Load and validate CBOR structure
        with open(filename_cbor, 'rb') as f:
            log_data = cbor2.loads(f.read())
            self.assertIsInstance(log_data, list)
            self.assertTrue(all("layer_hash" in entry for entry in log_data))

        # Clean up
        os.remove(filename_cbor)

    def test_full_integrity_verification(self):
        # Compute hash tree and verify against itself for full depth
        reference_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        result = self.hypha_crypt_hex.verify_integrity(reference_tree=reference_tree)
        self.assertTrue(result)

    def test_partial_integrity_verification(self):
        # Compute hash tree and verify partial depth integrity
        reference_tree = self.hypha_crypt_hex.compute_layered_hashes(layers=MAX_TREE_DEPTH)
        result = self.hypha_crypt_hex.verify_integrity(reference_tree=reference_tree, partial_depth=MAX_TREE_DEPTH // 2)
        self.assertTrue(result)

    def test_encryption_and_decryption(self):
        # Generate key, encrypt data, then decrypt it, verifying the result matches original data
        key = generate_encryption_key()
        encrypted_data = encrypt_data(self.data, key)
        decrypted_data = decrypt_data(encrypted_data, key)
        self.assertEqual(self.data, decrypted_data)

if __name__ == '__main__':
    unittest.main()
