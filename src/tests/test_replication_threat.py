import unittest
from unittest.mock import MagicMock
from src.dot_seigr.replication_threat import ThreatBasedReplication
from src.dot_seigr.replication_manager import ReplicationManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

class TestThreatBasedReplication(unittest.TestCase):

    def setUp(self):
        # Set up a mock ReplicationManager and initialize ThreatBasedReplication with it
        self.replication_manager = MagicMock(spec=ReplicationManager)
        self.threat_replicator = ThreatBasedReplication(self.replication_manager)
        
        # Default test parameters
        self.min_replication = 3
        self.segment_metadata = SegmentMetadata(segment_hash="test_segment_hash")

    def test_calculate_threat_replication_low_threat(self):
        # Test replication count for a low threat level
        threat_level = 1
        expected_replication_count = self.min_replication + 2
        replication_count = self.threat_replicator.calculate_threat_replication(threat_level, self.min_replication)
        
        self.assertEqual(replication_count, expected_replication_count)

    def test_calculate_threat_replication_high_threat(self):
        # Test replication count for a high threat level
        threat_level = 5
        expected_replication_count = self.min_replication + 5
        replication_count = self.threat_replicator.calculate_threat_replication(threat_level, self.min_replication)
        
        self.assertEqual(replication_count, expected_replication_count)

    def test_adaptive_threat_replication_success(self):
        # Test adaptive replication when replication is successful
        threat_level = 3
        replication_needed = self.min_replication + 3
        self.replication_manager.replicate_segment.return_value = True  # Simulate successful replication
        
        self.threat_replicator.adaptive_threat_replication(
            self.segment_metadata, threat_level, self.min_replication
        )
        
        # Ensure that replicate_segment was called with the correct replication count
        self.replication_manager.replicate_segment.assert_called_once_with(
            self.segment_metadata.segment_hash, replication_needed
        )

    def test_adaptive_threat_replication_failure(self):
        # Test adaptive replication failure handling
        threat_level = 4
        replication_needed = self.min_replication + 3
        self.replication_manager.replicate_segment.side_effect = Exception("Replication failed")
        
        with self.assertRaises(ValueError) as context:
            self.threat_replicator.adaptive_threat_replication(
                self.segment_metadata, threat_level, self.min_replication
            )
        
        # Verify that the exception message is correct
        self.assertIn("Replication failed for segment", str(context.exception))
        self.replication_manager.replicate_segment.assert_called_once_with(
            self.segment_metadata.segment_hash, replication_needed
        )

    def test_handle_high_risk_segments(self):
        # Test handle_high_risk_segments with a list of high-risk segments
        high_risk_segments = [
            SegmentMetadata(segment_hash="segment_1"),
            SegmentMetadata(segment_hash="segment_2"),
            SegmentMetadata(segment_hash="segment_3"),
        ]
        self.replication_manager.replicate_segment.return_value = True  # Simulate success for each segment

        with unittest.mock.patch.object(self.threat_replicator, 'adaptive_threat_replication') as mock_adaptive:
            self.threat_replicator.handle_high_risk_segments(high_risk_segments, self.min_replication)
            
            # Verify adaptive_threat_replication was called for each high-risk segment with the correct parameters
            self.assertEqual(mock_adaptive.call_count, len(high_risk_segments))
            for segment in high_risk_segments:
                mock_adaptive.assert_any_call(segment, threat_level=5, min_replication=self.min_replication)

if __name__ == '__main__':
    unittest.main()
