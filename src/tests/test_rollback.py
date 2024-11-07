import unittest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime
from src.dot_seigr.rollback import (
    rollback_to_previous_state,
    verify_rollback_availability,
    verify_layer_integrity,
    revert_segment_data,
    log_rollback_attempt,
    log_rollback_success
)
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import TemporalLayer

class TestRollback(unittest.TestCase):
    
    def setUp(self):
        # Create a mock SeigrFile instance with temporal layers
        self.seigr_file = MagicMock(spec=SeigrFile)
        self.seigr_file.hash = "test_segment_hash"
        self.seigr_file.temporal_layers = [
            TemporalLayer(layer_hash="initial_hash", timestamp="2023-01-01T00:00:00Z"),
            TemporalLayer(layer_hash="previous_hash", timestamp="2023-01-02T00:00:00Z"),
        ]

    def test_successful_rollback(self):
        # Mock integrity check and functions called within rollback
        with patch('src.dot_seigr.rollback.verify_layer_integrity', return_value=True), \
             patch('src.dot_seigr.rollback.log_rollback_attempt') as mock_log_attempt, \
             patch('src.dot_seigr.rollback.log_rollback_success') as mock_log_success, \
             patch('src.dot_seigr.rollback.revert_segment_data') as mock_revert_data:
             
            result = rollback_to_previous_state(self.seigr_file)
            
            # Verify that rollback was successful
            self.assertTrue(result)
            mock_log_attempt.assert_called_once_with(self.seigr_file.hash, "2023-01-01T00:00:00Z")
            mock_log_success.assert_called_once_with(self.seigr_file.hash, "2023-01-01T00:00:00Z")
            mock_revert_data.assert_called_once_with(self.seigr_file, self.seigr_file.temporal_layers[-2])

    def test_insufficient_temporal_layers(self):
        # Test when there are not enough layers for rollback
        self.seigr_file.temporal_layers = [TemporalLayer(layer_hash="initial_hash")]
        
        result = rollback_to_previous_state(self.seigr_file)
        
        # Verify rollback is unsuccessful due to insufficient layers
        self.assertFalse(result)

    def test_rollback_integrity_failure(self):
        # Mock integrity failure for previous layer
        with patch('src.dot_seigr.rollback.verify_layer_integrity', return_value=False):
            result = rollback_to_previous_state(self.seigr_file)
            
            # Verify rollback fails due to integrity check failure
            self.assertFalse(result)

    def test_verify_rollback_availability(self):
        # Test that availability is true when more than one layer is present
        result = verify_rollback_availability(self.seigr_file)
        self.assertTrue(result)

        # Test with insufficient layers
        self.seigr_file.temporal_layers = [TemporalLayer(layer_hash="only_layer")]
        result = verify_rollback_availability(self.seigr_file)
        self.assertFalse(result)

    def test_verify_layer_integrity(self):
        # Mock integrity check for layer
        previous_layer = self.seigr_file.temporal_layers[-2]
        expected_hash = "previous_hash"  # Set the expected hash for the test

        # Test integrity success
        previous_layer.layer_hash = "previous_hash"
        result = verify_layer_integrity(previous_layer, expected_hash)
        self.assertTrue(result)

        # Test integrity failure
        previous_layer.layer_hash = "mismatched_hash"
        result = verify_layer_integrity(previous_layer, expected_hash)
        self.assertFalse(result)

    def test_revert_segment_data(self):
        # Create a mock previous layer with data_snapshot entries as bytes
        previous_layer = TemporalLayer(
            layer_hash="prev_hash",
            data_snapshot={
                "data": b"old_data",  # Already bytes
                "primary_link": "old_primary_link".encode("utf-8"),  # Encode as bytes
                "secondary_links": json.dumps(["link1", "link2"]).encode("utf-8"),  # JSON serialized and encoded
                "coordinate_index": json.dumps({"x": 1, "y": 2, "z": 3}).encode("utf-8")  # JSON serialized and encoded
            }
        )
        
        with patch.object(self.seigr_file, 'add_temporal_layer') as mock_add_layer, \
            patch('src.dot_seigr.rollback.restore_metadata_links') as mock_restore_links, \
            patch('src.dot_seigr.rollback.restore_coordinate_index') as mock_restore_coord:
            
            # Call revert_segment_data with the mock layer
            revert_segment_data(self.seigr_file, previous_layer)
            
            # Assert data and hash were reverted
            self.assertEqual(self.seigr_file.data, previous_layer.data_snapshot["data"])
            self.assertEqual(self.seigr_file.hash, previous_layer.layer_hash)
            mock_restore_links.assert_called_once_with(self.seigr_file, previous_layer)
            mock_restore_coord.assert_called_once_with(self.seigr_file, previous_layer)
            mock_add_layer.assert_called_once()

    def test_log_rollback_attempt(self):
        with patch('src.dot_seigr.rollback.logger.info') as mock_logger_info:
            log_rollback_attempt("test_segment_hash", "2023-01-01T00:00:00Z")
            
            # Verify that the log entry is correctly formatted and logged
            mock_logger_info.assert_called_once()
            log_entry = mock_logger_info.call_args[0][0]
            self.assertIn("test_segment_hash", log_entry)
            self.assertIn("2023-01-01T00:00:00Z", log_entry)

    def test_log_rollback_success(self):
        with patch('src.dot_seigr.rollback.logger.info') as mock_logger_info:
            log_rollback_success("test_segment_hash", "2023-01-01T00:00:00Z")
            
            # Verify that the success log entry is correctly formatted and logged
            mock_logger_info.assert_called_once()
            log_entry = mock_logger_info.call_args[0][0]
            self.assertIn("test_segment_hash", log_entry)
            self.assertIn("2023-01-01T00:00:00Z", log_entry)

if __name__ == '__main__':
    unittest.main()
