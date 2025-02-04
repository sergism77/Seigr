import os
import shutil
import unittest
from unittest.mock import patch

from dot_seigr.seed_dot_seigr import SeedDotSeigr
from src.crypto.hypha_crypt import HyphaCrypt


class TestSeedDotSeigr(unittest.TestCase):

    def setUp(self):
        self.root_hash = "test_root_hash"
        self.seed_seigr = SeedDotSeigr(self.root_hash)
        self.test_directory = "test_clusters"

    def tearDown(self):
        # Clean up test directory after each test
        if os.path.exists(self.test_directory):
            shutil.rmtree(self.test_directory)

    def test_initialization(self):
        # Verify initialization sets correct root and seed hashes
        self.assertEqual(self.seed_seigr.root_hash, self.root_hash)
        self.assertEqual(self.seed_seigr.seed_hash, hypha_hash(self.root_hash.encode()))

    def test_add_segment_to_cluster(self):
        # Test adding a segment to the primary cluster
        segment_hash = "test_segment_hash"
        index = 1
        threat_level = 3

        self.seed_seigr.add_segment(segment_hash, index, threat_level)
        self.assertEqual(len(self.seed_seigr.cluster.segments), 1)
        self.assertEqual(self.seed_seigr.cluster.segments[0].segment_hash, segment_hash)
        self.assertEqual(self.seed_seigr.cluster.segments[0].segment_index, index)
        self.assertEqual(self.seed_seigr.cluster.segments[0].threat_level, threat_level)

    @patch(
        "src.dot_seigr.seed_dot_seigr.SeedDotSeigr._is_primary_cluster_full",
        return_value=True,
    )
    def test_create_new_secondary_cluster(self, mock_is_full):
        # Test that a secondary cluster is created when the primary cluster is full
        segment_hash = "test_segment_hash_secondary"
        index = 2
        threat_level = 2

        with patch.object(self.seed_seigr, "_create_new_cluster") as mock_create_new:
            self.seed_seigr.add_segment(segment_hash, index, threat_level)
            mock_create_new.assert_called_once_with(segment_hash, index, threat_level)

    def test_save_to_disk(self):
        # Test saving a cluster to disk
        file_path = self.seed_seigr.save_to_disk(self.test_directory)
        self.assertTrue(os.path.exists(file_path))

    def test_load_from_disk(self):
        # Test saving and loading cluster data from disk
        file_path = self.seed_seigr.save_to_disk(self.test_directory)

        # Create a new instance and load data
        loaded_seed = SeedDotSeigr(self.root_hash)
        loaded_seed.load_from_disk(file_path)

        self.assertEqual(loaded_seed.cluster.root_hash, self.seed_seigr.cluster.root_hash)
        self.assertEqual(loaded_seed.cluster.seed_hash, self.seed_seigr.cluster.seed_hash)

    def test_generate_cluster_report(self):
        # Test generating a report from the cluster
        segment_hash = "test_segment_hash"
        index = 1
        threat_level = 3
        self.seed_seigr.add_segment(segment_hash, index, threat_level)

        report = self.seed_seigr.generate_cluster_report()
        self.assertEqual(report["root_hash"], self.root_hash)
        self.assertEqual(report["seed_hash"], self.seed_seigr.seed_hash)
        self.assertEqual(report["segments"][0]["hash"], segment_hash)
        self.assertEqual(report["segments"][0]["index"], index)
        self.assertEqual(report["segments"][0]["threat_level"], threat_level)
        self.assertIn("secondary_clusters", report)
        self.assertFalse(report["secondary_cluster_active"])

    @patch("src.dot_seigr.seed_dot_seigr.time.time", return_value=1234567890)
    def test_ping_network(self, mock_time):
        # Test that ping updates the last_ping timestamp in the cluster
        self.seed_seigr.ping_network()
        self.assertEqual(self.seed_seigr.cluster.last_ping, 1234567890)

    @patch("builtins.print")
    def test_display_cluster_info(self, mock_print):
        # Test displaying cluster info to the console
        segment_hash = "test_segment_hash_display"
        index = 5
        threat_level = 1
        self.seed_seigr.add_segment(segment_hash, index, threat_level)

        self.seed_seigr.display_cluster_info()
        mock_print.assert_any_call(f"Root Hash: {self.seed_seigr.cluster.root_hash}")
        mock_print.assert_any_call(f"Seed Hash: {self.seed_seigr.cluster.seed_hash}")
        mock_print.assert_any_call("Segments:")
        mock_print.assert_any_call(
            f"  - Segment Index: {index}, Hash: {segment_hash}, Threat Level: {threat_level}"
        )


if __name__ == "__main__":
    unittest.main()
