import unittest

from src.dot_seigr.lineage import Lineage, LineageIntegrity


class TestLineageIntegrity(unittest.TestCase):

    def setUp(self):
        self.creator_id = "creator_123"
        self.lineage = Lineage(self.creator_id)

    def test_verify_integrity(self):
        # Retrieve the current hash to use as a reference
        reference_hash = self.lineage.current_hash
        # Use the correct static method to verify integrity
        self.assertTrue(
            LineageIntegrity.verify_integrity(self.lineage.current_hash, reference_hash)
        )

        # Simulate a tampered hash
        self.lineage.current_hash = "tampered_hash"
        self.assertFalse(
            LineageIntegrity.verify_integrity(self.lineage.current_hash, reference_hash)
        )


if __name__ == "__main__":
    unittest.main()
