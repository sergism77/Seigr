import unittest
from unittest.mock import MagicMock, patch
from src.replication.replication_self_heal import SelfHealReplication
from src.replication.replication_manager import ReplicationManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

class TestSelfHealReplication(unittest.TestCase):
    
    def setUp(self):
        # Mock ReplicationManager
        self.replication_manager = MagicMock(spec=ReplicationManager)
        self.self_heal_replicator = SelfHealReplication(self.replication_manager)
        
        # Default parameters for tests
        self.min_replication = 3
        self.segment_metadata = SegmentMetadata(segment_hash="test_segment_hash")
        
    def test_no_self_healing_needed(self):
        # Test that no self-healing is needed if network replication meets the minimum
        current_replication = 3
        network_replication = 3  # Meets the minimum replication requirement
        
        result = self.self_heal_replicator.check_and_self_heal(
            self.segment_metadata, current_replication, network_replication, self.min_replication
        )
        
        # Assert that no self-healing was triggered
        self.assertFalse(result)
        self.replication_manager.replicate_segment.assert_not_called()
    
    def test_self_healing_triggered(self):
        # Test that self-healing is triggered if network replication is below the minimum
        current_replication = 1
        network_replication = 2  # Below min_replication threshold of 3
        replication_needed = 1  # Additional replication needed to meet minimum
        
        self.replication_manager.replicate_segment.return_value = True
        
        result = self.self_heal_replicator.check_and_self_heal(
            self.segment_metadata, current_replication, network_replication, self.min_replication
        )
        
        # Assert that self-healing replication was triggered
        self.assertTrue(result)
        self.replication_manager.replicate_segment.assert_called_once_with(
            self.segment_metadata.segment_hash, replication_needed
        )

    def test_self_healing_failure_handling(self):
        # Test that an exception is raised if self-healing replication fails
        current_replication = 1
        network_replication = 1  # Below min_replication threshold
        replication_needed = 2  # Needs two more replications to meet minimum
        
        # Simulate failure in replication manager
        self.replication_manager.replicate_segment.side_effect = Exception("Replication failed")
        
        with self.assertRaises(ValueError) as context:
            self.self_heal_replicator.check_and_self_heal(
                self.segment_metadata, current_replication, network_replication, self.min_replication
            )
        
        # Verify that the exception message is correct
        self.assertIn("Replication failed for segment", str(context.exception))
        self.replication_manager.replicate_segment.assert_called_once_with(
            self.segment_metadata.segment_hash, replication_needed
        )

    def test_monitor_and_self_heal(self):
        # Test monitor_and_self_heal with multiple segments
        segments_status = {
            "segment_1": {
                "current_replication": 2,
                "network_replication": 2,  # Below min_replication threshold
                "segment_metadata": SegmentMetadata(segment_hash="hash1")
            },
            "segment_2": {
                "current_replication": 3,
                "network_replication": 3,  # Meets min_replication threshold
                "segment_metadata": SegmentMetadata(segment_hash="hash2")
            }
        }
        
        self.replication_manager.replicate_segment.return_value = True
        
        # Run the monitoring method
        with patch.object(self.self_heal_replicator, 'check_and_self_heal', wraps=self.self_heal_replicator.check_and_self_heal) as mock_check:
            self.self_heal_replicator.monitor_and_self_heal(segments_status, self.min_replication)
            
            # Assert check_and_self_heal was only called for the segment below threshold
            mock_check.assert_called_once_with(
                segments_status["segment_1"]["segment_metadata"],
                segments_status["segment_1"]["current_replication"],
                segments_status["segment_1"]["network_replication"],
                self.min_replication
            )

if __name__ == '__main__':
    unittest.main()
