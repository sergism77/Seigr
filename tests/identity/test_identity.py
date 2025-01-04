# src/tests/test_identity.py

import os
import unittest
from unittest import mock

from config import Config
from src.identity.seigr_identity import SeigrIdentity


class TestSeigrIdentity(unittest.TestCase):

    def setUp(self):
        # Use Config.SEIGR_ID_DIRECTORY for test files
        self.temp_directory = Config.SEIGR_ID_DIRECTORY
        if not os.path.exists(self.temp_directory):
            os.makedirs(self.temp_directory)
        self.identity_file = os.path.join(self.temp_directory, "test_seigr_id.dat")
        self.identity = SeigrIdentity()
        self.password = "test_password"

    def tearDown(self):
        # Clean up the test identity file after each test
        if os.path.exists(self.identity_file):
            os.remove(self.identity_file)
        # Clean up the directory if empty
        if os.path.exists(self.temp_directory) and not os.listdir(self.temp_directory):
            os.rmdir(self.temp_directory)

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

    def test_save_to_usb_and_load_from_usb(self):
        """Test saving and loading Seigr ID to and from a USB path with encryption."""
        self.identity.generate_seigr_id()
        self.identity.set_encryption_key(password=self.password)

        # Mock USB path and save the identity
        usb_path = os.path.join(self.temp_directory, "USB_Mock")
        os.makedirs(usb_path, exist_ok=True)
        self.identity.save_to_usb(usb_path)
        saved_file_path = os.path.join(
            usb_path,
            self.identity.USB_DIRECTORY_NAME,
            f"{self.identity.senary_id}.seigr",
        )
        self.assertTrue(
            os.path.exists(saved_file_path),
            "Expected identity file to be saved on USB.",
        )

        # Load the identity from USB
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_usb(usb_path, password=self.password)

        self.assertTrue(
            success, "Expected to successfully load and decrypt the Seigr ID from USB."
        )
        self.assertEqual(
            loaded_identity.senary_id,
            self.identity.senary_id,
            "Loaded Seigr ID should match the original ID.",
        )

    def test_save_without_encryption_key_raises_error(self):
        """Test saving without setting an encryption key raises ValueError."""
        self.identity.generate_seigr_id()
        with self.assertRaises(ValueError):
            self.identity.save_to_usb(self.temp_directory)

    def test_load_with_incorrect_password(self):
        """Test loading Seigr ID with an incorrect password fails."""
        self.identity.generate_seigr_id()
        self.identity.set_encryption_key(password=self.password)
        self.identity.save_to_usb(self.temp_directory)

        # Try loading with an incorrect password
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_usb(
            self.temp_directory, password="wrong_password"
        )
        self.assertFalse(success, "Expected loading to fail with incorrect password.")

    def test_verify_identity_with_correct_format(self):
        """Test verify_identity with a valid Seigr ID format."""
        seigr_id = self.identity.generate_seigr_id()
        is_valid = self.identity.verify_identity(seigr_id)
        self.assertTrue(
            is_valid, "Expected valid Seigr ID format to pass verification."
        )

    def test_verify_identity_with_incorrect_format(self):
        """Test verify_identity with an incorrect format or prefix."""
        invalid_id = (
            "1234567890"  # Invalid ID not starting with the senary-encoded prefix
        )
        is_valid = self.identity.verify_identity(invalid_id)
        self.assertFalse(
            is_valid, "Expected invalid Seigr ID format to fail verification."
        )

    @mock.patch("src.identity.seigr_identity.encrypt_data")
    @mock.patch("src.identity.seigr_identity.decrypt_data")
    def test_save_and_load_encryption_integration(self, mock_decrypt, mock_encrypt):
        """Test integration of encrypting and decrypting during save and load."""
        mock_encrypt.return_value = b"encrypted_data"
        mock_decrypt.return_value = self.identity.generate_seigr_id().encode()

        # Set up identity with encryption and save
        self.identity.set_encryption_key(password=self.password)
        self.identity.save_to_usb(self.temp_directory)

        # Load the identity and verify decryption
        loaded_identity = SeigrIdentity()
        success = loaded_identity.load_from_usb(
            self.temp_directory, password=self.password
        )
        self.assertTrue(success)
        mock_encrypt.assert_called_once()
        mock_decrypt.assert_called_once()
        self.assertEqual(loaded_identity.senary_id, self.identity.senary_id)

    @mock.patch("src.ipfs.ipfs_manager.IPFSManager.sync_files")
    def test_sync_with_ipfs(self, mock_sync_files):
        """Test IPFS sync functionality to verify data retrieval based on Seigr ID."""
        self.identity.generate_seigr_id()
        mock_sync_files.return_value = ["file1", "file2"]

        sync_result = self.identity.sync_with_ipfs()
        self.assertTrue(sync_result, "Expected IPFS sync to complete successfully.")
        mock_sync_files.assert_called_once_with(self.identity.senary_id)

    @mock.patch("src.identity.seigr_identity.SeigrIdentity.check_usb_connection")
    def test_check_usb_connection(self, mock_check_usb):
        """Test USB connection check returns expected path."""
        mock_check_usb.return_value = "/media/SeigrUSB"

        usb_path = self.identity.check_usb_connection()
        self.assertEqual(
            usb_path, "/media/SeigrUSB", "Expected USB path to be identified correctly."
        )
        mock_check_usb.assert_called_once()


if __name__ == "__main__":
    unittest.main()
