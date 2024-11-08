import unittest
from src.dot_seigr.lineage import Lineage, LineageSerializer
from src.dot_seigr.seigr_protocol.lineage_pb2 import Lineage as LineageProto

class TestLineageSerializer(unittest.TestCase):

    def setUp(self):
        self.creator_id = "creator_123"
        self.lineage = Lineage(self.creator_id)
        self.serializer = LineageSerializer(self.lineage)

    def test_to_protobuf(self):
        self.lineage.add_entry("create_file", "contributor_456")
        lineage_proto = self.serializer.to_protobuf()
        
        self.assertIsInstance(lineage_proto, LineageProto)
        self.assertEqual(lineage_proto.creator_id, self.creator_id)
        self.assertEqual(len(lineage_proto.entries), 1)
        
    def test_from_protobuf(self):
        lineage_proto = LineageProto(creator_id=self.creator_id, current_hash="test_hash", version="1.0")
        entry_proto = lineage_proto.entries.add(
            version="1.0",
            action="create_file",
            creator_id=self.creator_id,
            contributor_id="contributor_456",
            timestamp="2023-01-01T00:00:00+00:00"
        )
        entry_proto.previous_hashes.append("prev_hash")

        self.serializer.from_protobuf(lineage_proto)
        self.assertEqual(len(self.lineage.entries), 1)
        self.assertEqual(self.lineage.entries[0]["action"], "create_file")


if __name__ == "__main__":
    unittest.main()
