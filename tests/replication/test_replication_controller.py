import unittest
from unittest.mock import MagicMock

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.replication.replication_controller import ReplicationController
from src.replication.replication_demand import DemandBasedReplication
from src.replication.replication_self_heal import SelfHealReplication
from src.replication.replication_threat import ThreatBasedReplication


class TestReplicationController(unittest.TestCase):

    def setUp(self):
        # Mock network hyphens and create the ReplicationController instance
        self.network_hyphens = ["hyphen1", "hyphen2", "hyphen3"]
        self.min_replication = 2
        self.demand_threshold = 10

        # Initialize ReplicationController with mocked ReplicationManager
        self.replication_controller = ReplicationController(
            min_replication=self.min_replication,
            demand_threshold=self.demand_threshold,
            network_hyphens=self.network_hyphens,
        )

        # Mock the replicators in the ReplicationController
        self.replication_controller.demand_replicator = MagicMock(
            spec=DemandBasedReplication
        )
        self.replication_controller.threat_replicator = MagicMock(
            spec=ThreatBasedReplication
        )
        self.replication_controller.self_heal_replicator = MagicMock(
            spec=SelfHealReplication
        )

    def test_demand_replication_triggered(self):
        # Test that demand replication is triggered when access count exceeds threshold
        segment_metadata = SegmentMetadata(
            segment_hash="test_hash"
        )  # Set segment_hash directly
        segments_status = {
            "segment_1": {
                "segment_metadata": segment_metadata,
                "access_count": self.demand_threshold + 1,  # Exceeds threshold
                "threat_level": 0,
                "current_replication": 1,
                "network_replication": 1,
            }
        }

        # Run the controller's monitoring function
        self.replication_controller.monitor_and_adapt_replication(segments_status)

        # Verify that demand replication was triggered
        self.replication_controller.demand_replicator.adapt_based_on_demand.assert_called_once_with(
            segment_metadata,
            segments_status["segment_1"]["access_count"],
            self.demand_threshold,
            self.min_replication,
        )

    def test_threat_replication_triggered(self):
        # Test that threat replication is triggered when threat level is above zero
        segment_metadata = SegmentMetadata(
            segment_hash="test_hash"
        )  # Set segment_hash directly
        segments_status = {
            "segment_1": {
                "segment_metadata": segment_metadata,
                "access_count": 0,
                "threat_level": 2,  # Non-zero threat level
                "current_replication": 1,
                "network_replication": 1,
            }
        }

        # Run the controller's monitoring function
        self.replication_controller.monitor_and_adapt_replication(segments_status)

        # Verify that threat replication was triggered
        self.replication_controller.threat_replicator.adaptive_threat_replication.assert_called_once_with(
            segment_metadata,
            segments_status["segment_1"]["threat_level"],
            self.min_replication,
        )

    def test_self_healing_replication_triggered(self):
        # Test that self-healing replication is triggered when network replication is below minimum
        segment_metadata = SegmentMetadata(
            segment_hash="test_hash"
        )  # Set segment_hash directly
        segments_status = {
            "segment_1": {
                "segment_metadata": segment_metadata,
                "access_count": 0,
                "threat_level": 0,
                "current_replication": 1,
                "network_replication": self.min_replication
                - 1,  # Below min replication
            }
        }

        # Run the controller's monitoring function
        self.replication_controller.monitor_and_adapt_replication(segments_status)

        # Verify that self-healing replication was triggered
        self.replication_controller.self_heal_replicator.check_and_self_heal.assert_called_once_with(
            segment_metadata,
            segments_status["segment_1"]["current_replication"],
            segments_status["segment_1"]["network_replication"],
            self.min_replication,
        )

    def test_no_replication_when_conditions_not_met(self):
        # Test that no replication is triggered when conditions do not meet any thresholds
        segment_metadata = SegmentMetadata(
            segment_hash="test_hash"
        )  # Set segment_hash directly
        segments_status = {
            "segment_1": {
                "segment_metadata": segment_metadata,
                "access_count": self.demand_threshold - 1,  # Below threshold
                "threat_level": 0,  # No threat
                "current_replication": 2,
                "network_replication": 2,
            }
        }

        # Run the controller's monitoring function
        self.replication_controller.monitor_and_adapt_replication(segments_status)

        # Verify that no replication functions were called
        self.replication_controller.demand_replicator.adapt_based_on_demand.assert_not_called()
        self.replication_controller.threat_replicator.adaptive_threat_replication.assert_not_called()
        self.replication_controller.self_heal_replicator.check_and_self_heal.assert_not_called()


if __name__ == "__main__":
    unittest.main()
