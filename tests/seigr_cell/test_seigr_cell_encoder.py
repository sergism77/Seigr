# tests/seigr_cell/test_seigr_cell_encoder.py

import unittest
from datetime import datetime, timezone

from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_cell.seigr_cell_encoder import SeigrCellEncoder


class TestSeigrCellEncoder(unittest.TestCase):

    def setUp(self):
        self.segment_id = "test_segment"
        self.data = b"Sample data for encoding in Seigr Cell"
        self.metadata = {
            "contributor_id": "user_123",
            "tags": ["test", "seigr"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.password = "secure_password"
        self.encoder = SeigrCellEncoder(self.segment_id)

    def test_encode_data(self):
        """Test that data is encoded with encryption and integrity verification."""
        encoded_cell = self.encoder.encode(
            self.data, metadata=self.metadata, password=self.password
        )
        self.assertIsInstance(encoded_cell, bytes, "Encoded cell should be in bytes format")

    def test_decode_data(self):
        """Test that encoded data can be decoded back to its original form."""
        # Encode and then decode the data
        encoded_cell = self.encoder.encode(
            self.data, metadata=self.metadata, password=self.password
        )
        decoded_data, decoded_metadata = self.encoder.decode(encoded_cell, password=self.password)

        # Verify data integrity
        self.assertEqual(decoded_data, self.data, "Decoded data should match the original")
        self.assertEqual(
            decoded_metadata,
            self.metadata,
            "Decoded metadata should match the original metadata",
        )

    def test_integrity_verification(self):
        """Test integrity verification consistency between encoding and decoding."""
        encoded_cell = self.encoder.encode(
            self.data, metadata=self.metadata, password=self.password
        )
        decoded_data, decoded_metadata = self.encoder.decode(encoded_cell, password=self.password)

        # Simulate a hash check to validate integrity
        crypt_instance = HyphaCrypt(decoded_data, self.segment_id)
        computed_primary_hash = crypt_instance.compute_primary_hash()

        # Test that the primary hash matches the original hash from encoding
        self.assertEqual(
            self.encoder.hash_tree["primary_hash"],
            computed_primary_hash,
            "Primary hash should be consistent across encoding and decoding",
        )

    def test_decode_with_wrong_password(self):
        """Ensure decoding fails with an incorrect password."""
        encoded_cell = self.encoder.encode(
            self.data, metadata=self.metadata, password=self.password
        )

        with self.assertRaises(ValueError, msg="Decoding should fail with an incorrect password"):
            self.encoder.decode(encoded_cell, password="wrong_password")

    def test_integrity_failure_on_manipulation(self):
        """Test that integrity check fails if encoded data is tampered with."""
        encoded_cell = self.encoder.encode(
            self.data, metadata=self.metadata, password=self.password
        )

        # Tamper with the encoded cell to simulate corruption
        tampered_cell = bytearray(encoded_cell)
        tampered_cell[-1] ^= 0xFF  # Flip a bit in the last byte
        tampered_cell = bytes(tampered_cell)

        with self.assertRaises(
            ValueError, msg="Integrity verification should fail for tampered data"
        ):
            self.encoder.decode(tampered_cell, password=self.password)


if __name__ == "__main__":
    unittest.main()
