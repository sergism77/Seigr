import unittest
from unittest.mock import patch
from src.dot_seigr.integrity import verify_segment_integrity
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

class TestIntegrity(unittest.TestCase):

    def setUp(self):
        # Standard data and SegmentMetadata for tests
        self.valid_data = b"This is a valid data segment."
        self.corrupted_data = b"This data has been corrupted."
        self.segment_metadata = SegmentMetadata(
            segment_hash="validhash123456",
            data_hash="1:sha256:abcdef123456"  # Default expected hash format
        )

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:abcdef123456")
    def test_verify_segment_integrity_valid_segment(self, mock_hypha_hash):
        """
        Test that verify_segment_integrity returns True for valid data and metadata.
        """
        result = verify_segment_integrity(self.segment_metadata, self.valid_data)
        self.assertTrue(result, "Integrity check should pass for valid data and metadata.")

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:654321fedcba")
    def test_verify_segment_integrity_corrupted_segment(self, mock_hypha_hash):
        """
        Test that verify_segment_integrity returns False for corrupted data.
        """
        result = verify_segment_integrity(self.segment_metadata, self.corrupted_data)
        self.assertFalse(result, "Integrity check should fail for corrupted data.")

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:654321fedcba")
    def test_verify_segment_integrity_logging_on_failure(self, mock_hypha_hash):
        """
        Test that a failure in verify_segment_integrity logs a warning.
        """
        with self.assertLogs('src.dot_seigr.integrity', level='WARNING') as log:
            verify_segment_integrity(self.segment_metadata, self.corrupted_data)
            self.assertTrue(
                any("Integrity check failed" in message for message in log.output),
                "A warning should be logged on integrity check failure."
            )

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:nonmatchinghash")
    def test_verify_segment_integrity_empty_data(self, mock_hypha_hash):
        """
        Test that verify_segment_integrity returns False for empty data.
        """
        empty_data = b""
        result = verify_segment_integrity(self.segment_metadata, empty_data)
        self.assertFalse(result, "Integrity check should fail for empty data.")

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:partialhash123")
    def test_verify_segment_integrity_partial_data(self, mock_hypha_hash):
        """
        Test verify_segment_integrity with partial data, simulating incomplete transmission.
        """
        partial_data = self.valid_data[:10]
        result = verify_segment_integrity(self.segment_metadata, partial_data)
        self.assertFalse(result, "Integrity check should fail for incomplete data.")

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:specialhash123")
    def test_verify_segment_integrity_special_characters(self, mock_hypha_hash):
        """
        Test verify_segment_integrity with data containing special characters and encodings.
        """
        special_data = b"\x80\x81\x82\x83\xe2\x98\x83\xef\xb8\x8f"
        special_metadata = SegmentMetadata(
            segment_hash="specialhash123",
            data_hash="1:sha256:specialhash123"
        )
        result = verify_segment_integrity(special_metadata, special_data)
        self.assertTrue(result, "Integrity check should pass for data with special characters if hashes match.")

    def test_verify_segment_integrity_invalid_metadata_type(self):
        """
        Test verify_segment_integrity raises an error if SegmentMetadata is incorrectly provided.
        """
        with self.assertRaises(TypeError):
            verify_segment_integrity("InvalidMetadata", self.valid_data)

    @patch('src.dot_seigr.integrity.hypha_hash', return_value="1:sha256:hashforlargedata")
    def test_verify_segment_integrity_large_data(self, mock_hypha_hash):
        """
        Test verify_segment_integrity with large data segments to assess performance and memory handling.
        """
        large_data = b"A" * 10**6  # 1 MB of data for testing
        large_metadata = SegmentMetadata(
            segment_hash="hashforlargedata",
            data_hash="1:sha256:hashforlargedata"
        )
        result = verify_segment_integrity(large_metadata, large_data)
        self.assertTrue(result, "Integrity check should pass for large data segments if hash matches.")

if __name__ == "__main__":
    unittest.main()
