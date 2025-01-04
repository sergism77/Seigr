import unittest
from unittest import TestCase, mock

from dot_seigr.core.seigr_file import SeigrFile
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.immune_system.immune_system import ImmuneSystem


class TestImmuneSystem(TestCase):

    def setUp(self):
        # Mock ReplicationController and its methods
        self.replication_controller = mock.Mock()
        self.replication_controller.threat_replicator = mock.Mock()
        self.replication_controller.trigger_security_replication = mock.Mock()

        # Initialize ImmuneSystem with mocks and clear threat log
        self.immune_system = ImmuneSystem(
            monitored_segments={},
            replication_controller=self.replication_controller,
            critical_threshold=3,
        )
        self.immune_system.threat_detector.threat_log = (
            []
        )  # Ensure clean threat log before each test

    @mock.patch("src.dot_seigr.integrity.verify_segment_integrity")
    def test_immune_ping_fails_with_corrupted_data(self, mock_verify_integrity):
        """Test that immune_ping logs a threat and returns False for corrupted data."""
        # Mock integrity check to simulate failure
        mock_verify_integrity.return_value = False
        raw_data = b"corrupted_data"
        segment_metadata = SegmentMetadata(
            creator_id="test_creator",
            segment_index=1,
            segment_hash="xyz789",
            timestamp="2023-01-01T00:00:00Z",
            data_hash="expected_hash",
        )

        # Call immune_ping
        result = self.immune_system.immune_ping(segment_metadata, data=raw_data)

        # Assertions
        self.assertFalse(
            result, "Expected immune_ping to return False for corrupted integrity"
        )
        self.assertEqual(
            len(self.immune_system.threat_detector.threat_log),
            1,
            "Expected a single threat to be logged",
        )
        self.assertEqual(
            self.immune_system.threat_detector.threat_log[0]["segment_hash"],
            segment_metadata.segment_hash,
            "Expected the logged threat to match the segment hash",
        )

    @mock.patch("src.immune_system.rollback_handling.rollback_to_previous_state")
    @mock.patch(
        "src.immune_system.rollback_handling.RollbackHandler.verify_rollback_availability",
        return_value=True,
    )
    def test_rollback_segment_invokes_rollback_to_previous_state(
        self, mock_verify_rollback_availability, mock_rollback
    ):
        """Test that rollback_segment calls rollback_to_previous_state when availability is verified."""
        seigr_file = mock.create_autospec(SeigrFile)
        seigr_file.hash = "mock_hash"
        seigr_file.metadata = mock.Mock()
        seigr_file.metadata.primary_link = "current_primary_link"
        seigr_file.metadata.secondary_links = ["current_link1"]

        # Mock temporal layers
        previous_layer = mock.Mock()
        previous_layer.layer_hash = b"previous_hash"
        previous_layer.expected_hash = b"previous_hash"
        previous_layer.data_snapshot = {
            "data": b"previous_data",
            "primary_link": "previous_primary_link",
            "secondary_links": ["link1", "link2"],
            "coordinate_index": mock.Mock(),
        }
        seigr_file.temporal_layers = [previous_layer, mock.Mock()]

        # Invoke rollback_segment
        self.immune_system.rollback_segment(seigr_file)

        # Check that rollback was called correctly
        self.assertEqual(
            mock_rollback.call_count,
            1,
            "Expected rollback_to_previous_state to be called once.",
        )
        self.assertEqual(
            mock_rollback.call_args[0][0],
            seigr_file,
            "Expected rollback_to_previous_state to be called with the correct seigr_file.",
        )

    @mock.patch("src.immune_system.rollback_handling.rollback_to_previous_state")
    @mock.patch(
        "src.immune_system.rollback_handling.RollbackHandler.verify_rollback_availability",
        return_value=False,
    )
    def test_rollback_segment_does_not_invoke_when_unavailable(
        self, mock_verify_rollback_availability, mock_rollback
    ):
        """Test that rollback_segment does not invoke rollback when availability check fails."""
        seigr_file = mock.create_autospec(SeigrFile)
        seigr_file.hash = "mock_hash"
        seigr_file.temporal_layers = []

        # Invoke rollback_segment
        self.immune_system.rollback_segment(seigr_file)

        # Assert rollback was not called
        self.assertEqual(
            mock_rollback.call_count,
            0,
            "Expected rollback_to_previous_state not to be called when unavailable.",
        )


if __name__ == "__main__":
    unittest.main()
