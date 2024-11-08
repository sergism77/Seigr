import unittest
from src.dot_seigr.lineage.lineage_entry import LineageEntry

class TestLineageEntry(unittest.TestCase):
    def setUp(self):
        self.version = "1.0"
        self.action = "create"
        self.creator_id = "creator_123"
        self.contributor_id = "contrib_456"
        self.previous_hashes = ["hash1", "hash2"]
        self.metadata = {"info": "Sample metadata"}
        
        # Initialize LineageEntry with the correct arguments
        self.lineage_entry = LineageEntry(
            version=self.version,
            action=self.action,
            creator_id=self.creator_id,
            contributor_id=self.contributor_id,
            previous_hashes=self.previous_hashes,
            metadata=self.metadata
        )

    def test_create_entry(self):
        # Implement the test assertions for LineageEntry here
        self.assertEqual(self.lineage_entry.action, self.action)
        self.assertEqual(self.lineage_entry.creator_id, self.creator_id)
        self.assertEqual(self.lineage_entry.contributor_id, self.contributor_id)
        self.assertEqual(self.lineage_entry.previous_hashes, self.previous_hashes)
        self.assertEqual(self.lineage_entry.metadata, self.metadata)

if __name__ == "__main__":
    unittest.main()
