import os
import unittest
from datetime import datetime
from datetime import timezone
from unittest.mock import patch, MagicMock
from dot_seigr.core.seigr_file import SeigrFile
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata, AccessContext

class TestSeigrFile(unittest.TestCase):
    
    def setUp(self):
        self.data = b"sample data for SeigrFile"
        self.creator_id = "test_creator"
        self.index = 1
        self.file_type = "senary"
        self.seigr_file = SeigrFile(self.data, self.creator_id, self.index, self.file_type)
        
    def test_initialization(self):
        """Test that SeigrFile initializes correctly with expected metadata."""
        self.assertEqual(self.seigr_file.creator_id, self.creator_id)
        self.assertEqual(self.seigr_file.index, self.index)
        self.assertEqual(self.seigr_file.file_type, self.file_type)
        self.assertIsInstance(self.seigr_file.metadata, SegmentMetadata)
        self.assertEqual(self.seigr_file.metadata.creator_id, self.creator_id)
        self.assertEqual(self.seigr_file.metadata.segment_index, self.index)

    def test_set_links(self):
        """Test setting primary and secondary links."""
        primary_link = "primary_link_hash"
        secondary_links = ["secondary_link_1", "secondary_link_2"]
        self.seigr_file.set_links(primary_link, secondary_links)
        
        links = self.seigr_file.link_manager.get_links()
        self.assertEqual(links["primary"], primary_link)
        self.assertEqual(links["secondary"], secondary_links)

    @patch('src.dot_seigr.seigr_file.datetime', wraps=datetime)
    def test_add_temporal_layer(self, mock_datetime):
        """Test adding a temporal layer snapshot."""
        mock_datetime.now.return_value = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # Ensure UTC timezone
        self.seigr_file.add_temporal_layer()

        self.assertEqual(len(self.seigr_file.temporal_layers), 1)
        temporal_layer = self.seigr_file.temporal_layers[0]
        self.assertEqual(temporal_layer.timestamp, "2023-01-01T00:00:00+00:00")  # Expected format with timezone
        self.assertTrue(temporal_layer.layer_hash)

    def test_record_access(self):
        """Test recording hyphen access updates access context."""
        hyphen_id = "hyphen_123"
        self.seigr_file.record_access(hyphen_id)

        self.assertEqual(self.seigr_file.access_context.access_count, 1)
        self.assertIn(hyphen_id, self.seigr_file.access_context.hyphen_access_history)

    @patch("src.dot_seigr.seigr_file.os.makedirs")
    @patch("src.dot_seigr.seigr_file.open", new_callable=unittest.mock.mock_open)
    def test_save_to_disk_protobuf(self, mock_open, mock_makedirs):
        """Test saving .seigr file to disk in Protobuf format."""
        base_dir = "test_dir"
        file_path = self.seigr_file.save_to_disk(base_dir, use_cbor=False)

        self.assertTrue(file_path.endswith(".pb"))
        mock_makedirs.assert_called_once_with(base_dir, exist_ok=True)
        mock_open.assert_called_once()

    @patch("src.dot_seigr.seigr_file.os.makedirs")
    @patch("src.dot_seigr.seigr_file.open", new_callable=unittest.mock.mock_open)
    def test_save_to_disk_cbor(self, mock_open, mock_makedirs):
        """Test saving .seigr file to disk in CBOR format."""
        base_dir = "test_dir"
        file_path = self.seigr_file.save_to_disk(base_dir, use_cbor=True)

        self.assertTrue(file_path.endswith(".cbor"))
        mock_makedirs.assert_called_once_with(base_dir, exist_ok=True)
        mock_open.assert_called_once()

    def test_add_coordinate_index(self):
        """Test adding a 3D coordinate index."""
        x, y, z = 1, 2, 3
        self.seigr_file.add_coordinate_index(x, y, z)

        coord_index = self.seigr_file.metadata.coordinate_index
        self.assertEqual(coord_index.x, x)
        self.assertEqual(coord_index.y, y)
        self.assertEqual(coord_index.z, z)

    def test_data_integrity_hash(self):
        """Test that data hash is generated and matches expected."""
        expected_data_hash = hypha_hash(self.data)
        self.assertEqual(self.seigr_file.data_hash, expected_data_hash)

    def test_access_context_initialization(self):
        """Test initialization of access context."""
        self.assertIsInstance(self.seigr_file.access_context, AccessContext)
        self.assertEqual(self.seigr_file.access_context.access_count, 0)

    @patch("src.dot_seigr.seigr_file.HyphaCrypt")
    def test_encryption_initialization(self, mock_hypha_crypt):
        """Test that encryption and primary hash are initialized."""
        mock_crypt_instance = MagicMock()
        mock_hypha_crypt.return_value = mock_crypt_instance
        mock_crypt_instance.compute_primary_hash.return_value = "mocked_primary_hash"

        test_file = SeigrFile(self.data, self.creator_id, self.index, self.file_type)
        self.assertEqual(test_file.hash, "mocked_primary_hash")

if __name__ == "__main__":
    unittest.main()
