import unittest

from src.crypto.hypha_crypt import hypha_hash
from src.dot_seigr.lineage import Lineage


class TestLineage(unittest.TestCase):

    def setUp(self):
        self.creator_id = "creator_123"
        self.initial_hash = hypha_hash(self.creator_id.encode())
        self.lineage = Lineage(self.creator_id, initial_hash=self.initial_hash)

    def test_add_entry(self):
        action = "created_file"
        contributor_id = "contributor_456"
        self.lineage.add_entry(action, contributor_id)

        self.assertEqual(len(self.lineage.entries), 1)
        entry = self.lineage.entries[0]
        self.assertEqual(entry["action"], action)
        self.assertEqual(entry["contributor_id"], contributor_id)


if __name__ == "__main__":
    unittest.main()
