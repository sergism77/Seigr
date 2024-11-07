import unittest
from unittest import TestCase, mock
from src.dot_seigr.immune_system import ImmuneSystem
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.dot_seigr.seigr_file import SeigrFile
from src.crypto.hash_utils import hypha_hash

class TestImmuneSystem(TestCase):

    def setUp(self):
        # Mock ReplicationController and its methods
        self.replication_controller = mock.Mock()
        self.replication_controller.threat_replicator = mock.Mock()
        self.replication_controller.trigger_security_replication = mock.Mock()

        # Initialize ImmuneSystem with mocks
        self.immune_system = ImmuneSystem(
            monitored_segments={},
            replication_controller=self.replication_controller,
            replication_threshold=3,
            adaptive_threshold=5,
            max_threat_log_size=1000
        )

    @mock.patch('src.dot_seigr.integrity.verify_segment_integrity')
    def test_immune_ping_passes_with_valid_integrity(self, mock_verify_integrity):
        """
        Test that immune_ping returns True and logs no threat for valid data.
        """
        # Mock SegmentMetadata with an accurate data_hash to match raw_data hash
        raw_data = b"valid_data"
        expected_data_hash = hypha_hash(raw_data)

        segment_metadata = SegmentMetadata(
            creator_id="test_creator",
            segment_index=0,
            segment_hash="abc123",
            timestamp="2023-01-01T00:00:00Z",
            data_hash=expected_data_hash
        )

        # Set mock to return True, simulating a passing integrity check
        mock_verify_integrity.return_value = True

        # Call immune_ping and check that it returns True
        result = self.immune_system.immune_ping(segment_metadata, data=raw_data)
        
        # Assertions
        self.assertTrue(result, "Expected immune_ping to return True for valid integrity")
        self.assertEqual(len(self.immune_system.threat_log), 0, "Expected no threats to be logged")

    @mock.patch('src.dot_seigr.integrity.verify_segment_integrity')
    def test_immune_ping_fails_with_corrupted_data(self, mock_verify_integrity):
        """
        Test that immune_ping logs a threat and returns False for corrupted data.
        """
        # Set up corrupted data scenario
        raw_data = b"corrupted_data"
        segment_metadata = SegmentMetadata(
            creator_id="test_creator",
            segment_index=1,
            segment_hash="xyz789",
            timestamp="2023-01-01T00:00:00Z",
            data_hash="expected_hash"
        )

        # Set mock to return False, simulating a failing integrity check
        mock_verify_integrity.return_value = False

        # Call immune_ping and expect it to return False
        result = self.immune_system.immune_ping(segment_metadata, data=raw_data)
        
        # Assertions
        self.assertFalse(result, "Expected immune_ping to return False for corrupted integrity")
        self.assertEqual(len(self.immune_system.threat_log), 1, "Expected a threat to be logged")
        self.assertEqual(self.immune_system.threat_log[0]["segment_hash"], segment_metadata.segment_hash)

    @mock.patch('src.dot_seigr.rollback.rollback_to_previous_state')
    @mock.patch('src.dot_seigr.rollback.verify_rollback_availability', return_value=True)
    def test_rollback_segment_invokes_rollback_to_previous_state(self, mock_verify_rollback_availability, mock_rollback):
        """
        Test that rollback_segment calls rollback_to_previous_state when available.
        """
        # Set up SeigrFile mock with valid temporal_layers and metadata
        seigr_file = mock.create_autospec(SeigrFile)
        seigr_file.hash = "mock_hash"
        
        # Mock metadata for seigr_file
        seigr_file.metadata = mock.Mock()
        seigr_file.metadata.primary_link = "current_primary_link"
        seigr_file.metadata.secondary_links = ["current_link1"]

        # Set up valid previous_layer with required data_snapshot
        previous_layer = mock.Mock()
        previous_layer.layer_hash = "previous_hash"
        previous_layer.expected_hash = "previous_hash"
        previous_layer.data_snapshot = {
            "data": b"previous_data",
            "primary_link": "previous_primary_link",
            "secondary_links": ["link1", "link2"],
            "coordinate_index": mock.Mock()
        }
        
        # Assign temporal_layers to include previous and current layer
        seigr_file.temporal_layers = [previous_layer, mock.Mock()]

        # Invoke rollback_segment
        self.immune_system.rollback_segment(seigr_file)
        
        # Check that rollback_to_previous_state was called
        self.assertEqual(mock_rollback.call_count, 1, "Expected rollback_to_previous_state to be called once.")

    @mock.patch('src.dot_seigr.rollback.rollback_to_previous_state')
    @mock.patch('src.dot_seigr.rollback.verify_rollback_availability', return_value=False)
    def test_rollback_segment_does_not_invoke_when_unavailable(self, mock_verify_rollback_availability, mock_rollback):
        """
        Test that rollback_segment does not invoke rollback if unavailable.
        """
        # Set up SeigrFile mock with no temporal_layers
        seigr_file = mock.create_autospec(SeigrFile)
        seigr_file.hash = "mock_hash"
        seigr_file.temporal_layers = []  # No previous layers available

        # Invoke rollback_segment and check no rollback attempt is made
        self.immune_system.rollback_segment(seigr_file)
        self.assertEqual(mock_rollback.call_count, 0, "Expected rollback_to_previous_state not to be called when unavailable.")

if __name__ == "__main__":
    unittest.main()
