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

@mock.patch('src.dot_seigr.rollback.rollback_to_previous_state')
@mock.patch('src.dot_seigr.rollback.verify_rollback_availability', return_value=True)
def test_rollback_segment_invokes_rollback_to_previous_state(self, mock_verify_rollback_availability, mock_rollback):
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

    # Debug output to confirm the setup
    print(f"Debug: seigr_file.temporal_layers = {seigr_file.temporal_layers}")
    print(f"Debug: seigr_file.hash = {seigr_file.hash}")
    print(f"Debug: rollback_allowed = {mock_verify_rollback_availability.return_value}")

    # Log initial state of mock call count
    print(f"Debug: Initial call count of mock_rollback = {mock_rollback.call_count}")

    # Invoke rollback_segment
    self.immune_system.rollback_segment(seigr_file)
    
    # Check that rollback_to_previous_state was called
    print(f"Debug: Final call count of mock_rollback after invocation = {mock_rollback.call_count}")
    self.assertEqual(mock_rollback.call_count, 1, "Expected rollback_to_previous_state to be called once.")
