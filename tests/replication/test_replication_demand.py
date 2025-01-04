import unittest
from unittest.mock import MagicMock, patch

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.replication.replication_demand import DemandBasedReplication
from src.replication.replication_manager import ReplicationManager


class TestDemandBasedReplication(unittest.TestCase):

    def setUp(self):
        # Mock ReplicationManager
        self.replication_manager = MagicMock(spec=ReplicationManager)
        self.demand_replicator = DemandBasedReplication(self.replication_manager)

        # Default test parameters
        self.demand_threshold = 10
        self.min_replication = 2
        self.segment_metadata = SegmentMetadata(segment_hash="test_segment_hash")

    def test_no_replication_below_threshold(self):
        # Verify no replication occurs if access count is below threshold
        access_count = 5  # Below demand threshold
        result = self.demand_replicator.adapt_based_on_demand(
            self.segment_metadata,
            access_count,
            self.demand_threshold,
            self.min_replication,
        )

        # Assert that no replication was triggered
        self.assertFalse(result)
        self.replication_manager.replicate_segment.assert_not_called()

    def test_replication_triggered_above_threshold(self):
        # Test that replication is triggered if access count exceeds threshold
        access_count = 15  # Above demand threshold
        self.replication_manager.replicate_segment.return_value = True

        result = self.demand_replicator.adapt_based_on_demand(
            self.segment_metadata,
            access_count,
            self.demand_threshold,
            self.min_replication,
        )

        # Assert that replication was triggered
        self.assertTrue(result)
        self.replication_manager.replicate_segment.assert_called_once()

    def test_calculate_demand_scale_low_demand(self):
        # Test scaling function for low demand
        access_count = 15
        expected_replication_count = 3  # Corresponds to low demand level
        replication_count = self.demand_replicator.calculate_demand_scale(
            access_count, self.min_replication
        )

        self.assertEqual(replication_count, expected_replication_count)

    def test_calculate_demand_scale_high_demand(self):
        # Test scaling function for high demand
        access_count = 1500
        expected_replication_count = 12  # High demand level
        replication_count = self.demand_replicator.calculate_demand_scale(
            access_count, self.min_replication
        )

        self.assertEqual(replication_count, expected_replication_count)

    def test_replication_failure_handling(self):
        # Test that a ValueError is raised if replication fails
        access_count = 20  # Above threshold
        self.replication_manager.replicate_segment.side_effect = Exception(
            "Replication failed"
        )

        # Expect adapt_based_on_demand to raise a ValueError when replicate_segment fails
        with self.assertRaises(ValueError) as context:
            self.demand_replicator.adapt_based_on_demand(
                self.segment_metadata,
                access_count,
                self.demand_threshold,
                self.min_replication,
            )

        # Verify that the exception message includes the segment hash and failure message
        self.assertIn("Replication failed for segment", str(context.exception))
        self.replication_manager.replicate_segment.assert_called_once_with(
            self.segment_metadata.segment_hash,
            3,  # Expected replication count for low demand
        )

    def test_monitor_and_replicate_by_demand(self):
        # Test monitor_and_replicate_by_demand with multiple segments
        segments_status = {
            "segment_1": {
                "access_count": 5,  # Below threshold
                "segment_metadata": SegmentMetadata(segment_hash="hash1"),
            },
            "segment_2": {
                "access_count": 20,  # Above threshold
                "segment_metadata": SegmentMetadata(segment_hash="hash2"),
            },
        }

        self.replication_manager.replicate_segment.return_value = True

        # Run the monitoring method
        with patch.object(
            self.demand_replicator,
            "adapt_based_on_demand",
            wraps=self.demand_replicator.adapt_based_on_demand,
        ) as mock_adapt:
            self.demand_replicator.monitor_and_replicate_by_demand(
                segments_status, self.demand_threshold, self.min_replication
            )

            # Verify that adapt_based_on_demand was called only for the segment above threshold
            mock_adapt.assert_called_once_with(
                segments_status["segment_2"]["segment_metadata"],
                segments_status["segment_2"]["access_count"],
                self.demand_threshold,
                self.min_replication,
            )


if __name__ == "__main__":
    unittest.main()
