import unittest
import os
from tempfile import TemporaryDirectory
from src.dot_seigr.lineage import Lineage, LineageSerializer, LineageStorage

class TestLineageStorage(unittest.TestCase):

    def setUp(self):
        self.creator_id = "creator_123"
        self.lineage = Lineage(self.creator_id)
        self.serializer = LineageSerializer(self.lineage)
        self.storage = LineageStorage(self.serializer)

    def test_save_to_disk(self):
        with TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "lineage.pb")
            self.lineage.add_entry("create_file", "contributor_456")
            
            self.storage.save_to_disk(file_path)
            self.assertTrue(os.path.exists(file_path))

    def test_load_from_disk(self):
        with TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "lineage.pb")
            self.lineage.add_entry("update_metadata", "contributor_789")
            self.storage.save_to_disk(file_path)

            new_lineage = Lineage(self.creator_id)
            new_serializer = LineageSerializer(new_lineage)
            new_storage = LineageStorage(new_serializer)
            new_storage.load_from_disk(file_path)
            
            self.assertEqual(len(new_lineage.entries), 1)
            self.assertEqual(new_lineage.entries[0]["action"], "update_metadata")


if __name__ == "__main__":
    unittest.main()
