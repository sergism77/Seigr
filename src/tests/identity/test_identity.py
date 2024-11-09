# src/tests/test_identity.py

import unittest
import os
from unittest import mock
from src.identity.seigr_identity import SeigrIdentity
from src.crypto.hypha_crypt import generate_encryption_key
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeigrIdentityData
from config import Config

class TestSeigrIdentity(unittest.TestCase):

    def setUp(self):
        # Set up a temporary directory for saving the identity file
        if not os.path.exists(Config.SEIGR_ID_DIRECTORY):
            os.makedirs(Config.SEIGR_ID_DIRECTORY)
        self.identity_file = os.path.join(Config.SEIGR_ID_DIRECTORY, "test_seigr_id.dat")
        self.identity = SeigrIdentity()
        self.password = "test_password"
        
    def tearDown(self):
        # Clean up by removing the test identity file after each test
        if os.path.exists(self.identity_file):
            os.remove(self.identity_file)

    def test_generate_seigr_id(self):
        """Test Seigr ID generation with the correct senary prefix."""
        seigr_id = self.identity.generate_seigr_id()
        
        # Ensure the Seigr ID starts with the correct prefix and matches the expected length
        self.assertTrue(seigr_id.startswith(SeigrIdentity.SEIGR_PREFIX))
        self.assertEqual(len(seigr_id), len(self.identity.senary_id))

    def test_set_encryption_key_with_password(self):
        """Test setting encryption key using a password."""
        self.identity.set_encryption_key(password=self.password)
        self.assertIsNotNone(self.identity.encryption_key)

    def test_save_to_external_and_load_from_external(self):
        """Test saving and loading Seigr ID with encryption."""
        self.identity.generate_seigr_id()
        self.identity.set_encryption_key(password=self.password)
        
        # Save the identity to an external file
        self.identity.save_to_external(self.identity_file)
        self.assertTrue(os.path.exists(self.identity_file), "Expected identity file to be saved.")

        # Create a new SeigrIdentity instance and load the saved data
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_external(self.identity_file, password=self.password)
        
        self.assertTrue(success, "Expected to successfully load and decrypt the Seigr ID.")
        self.assertEqual(loaded_identity.senary_id, self.identity.senary_id, "Loaded Seigr ID should match the original ID.")

    def test_save_without_encryption_key_raises_error(self):
        """Test saving without setting an encryption key raises ValueError."""
        self.identity.generate_seigr_id()
        with self.assertRaises(ValueError):
            self.identity.save_to_external(self.identity_file)

    def test_load_with_incorrect_password(self):
        """Test loading Seigr ID with an incorrect password fails."""
        self.identity.generate_seigr_id()
        self.identity.set_encryption_key(password=self.password)
        self.identity.save_to_external(self.identity_file)

        # Try loading with an incorrect password
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_external(self.identity_file, password="wrong_password")
        self.assertFalse(success, "Expected loading to fail with incorrect password.")

    def test_verify_identity_with_correct_format(self):
        """Test verify_identity with a valid Seigr ID format."""
        seigr_id = self.identity.generate_seigr_id()
        is_valid = self.identity.verify_identity(seigr_id)
        self.assertTrue(is_valid, "Expected valid Seigr ID format to pass verification.")

    def test_verify_identity_with_incorrect_format(self):
        """Test verify_identity with an incorrect format or prefix."""
        invalid_id = "1234567890"  # Invalid ID not starting with "seigr" prefix
        is_valid = self.identity.verify_identity(invalid_id)
        self.assertFalse(is_valid, "Expected invalid Seigr ID format to fail verification.")

    @mock.patch("src.identity.seigr_identity.encrypt_data")
    @mock.patch("src.identity.seigr_identity.decrypt_data")
    def test_save_and_load_encryption_integration(self, mock_decrypt, mock_encrypt):
        """Test integration of encrypting and decrypting during save and load."""
        mock_encrypt.return_value = b"encrypted_data"
        mock_decrypt.return_value = self.identity.generate_seigr_id().encode()

        # Set up identity with encryption and save
        self.identity.set_encryption_key(password=self.password)
        self.identity.save_to_external(self.identity_file)

        # Load the identity and verify decryption
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_external(self.identity_file, password=self.password)
        self.assertTrue(success)
        mock_encrypt.assert_called_once()
        mock_decrypt.assert_called_once()
        self.assertEqual(loaded_identity.senary_id, self.identity.senary_id)

if __name__ == "__main__":
    unittest.main()
