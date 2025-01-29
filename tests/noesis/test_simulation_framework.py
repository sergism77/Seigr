import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from src.noesis.data_preprocessor import DataPreprocessor
from src.noesis.task_executor import TaskExecutor
from src.noesis.sync_manager import SyncManager
from src.noesis.monitoring import MonitoringService
from src.seigr_protocol.compiled.noesis_pb2 import (
    NoesisTask,
    TaskOutcome,
    NoesisConfig,
    TaskResult,
    MonitoringRequest,
    NoesisMonitoring,
)


class TestSimulationFramework(unittest.TestCase):
    """
    A test framework for the Seigr ecosystem that validates the functionality,
    performance, and reliability of core modules through automated tests.
    """

    def setUp(self):
        """
        Sets up the environment for testing, including mock objects and initial configurations.
        """
        # Initialize core components
        self.preprocessor = DataPreprocessor()
        self.task_executor = TaskExecutor()
        self.sync_manager = SyncManager()
        self.monitoring_service = MonitoringService()

        # Test data for simulation
        self.raw_data = [
            {"id": "123", "value": 75.0, "timestamp": "2025-01-01T12:00:00Z"},
            {"id": "124", "value": -25.0, "timestamp": "2025-01-01T12:01:00Z"},
            {"id": "125", "value": 150.0, "timestamp": "2025-01-01T12:02:00Z"},
        ]

        # Mock configurations
        self.test_config = {
            "config_id": "test_config_001",
            "metadata": {"environment": "test"},
        }

        # Mock task
        self.test_task = NoesisTask(
            task_id="test_task_001",
            task_type=2,  # TASK_INFERENCE
            data_sources=["source_1", "source_2"],
            task_metadata={"pipeline_id": "test_pipeline_001"},
        )

    def test_preprocessor_pipeline(self):
        """
        Validates the full preprocessing pipeline, ensuring data is cleaned and normalized.
        """
        # Run preprocessing
        preprocessed_data = self.preprocessor.preprocess(self.raw_data)

        # Assertions
        self.assertEqual(len(preprocessed_data), 3)
        for entry in preprocessed_data:
            self.assertIn("id", entry)
            self.assertIn("value", entry)
            self.assertIn("timestamp", entry)
            self.assertGreaterEqual(entry["value"], 0)  # Ensure normalization is applied

    def test_task_execution(self):
        """
        Ensures that the TaskExecutor correctly executes tasks and returns valid results.
        """
        with patch.object(
            self.task_executor,
            "execute",
            return_value=TaskResult(
                task_id=self.test_task.task_id,  # ✅ Corrected field
                outcome=TaskOutcome.TASK_SUCCESS,
                message="Task executed successfully.",
                result_metadata={"result": "success", "metrics": {"accuracy": 0.95}},  # ✅ Fixed dictionary
            ),
        ) as mock_execute:
            # Execute task
            result = self.task_executor.execute(self.test_task)

            # Assertions
            self.assertEqual(result.task_id, self.test_task.task_id)
            self.assertEqual(result.outcome, TaskOutcome.TASK_SUCCESS)
            self.assertEqual(result.result_metadata["result"], "success")
            self.assertIn("metrics", result.result_metadata)
            mock_execute.assert_called_once()

    def test_sync_manager(self):
        """
        Validates state synchronization and conflict resolution.
        """
        # Prepare mock state data
        state_id = "test_state_001"
        local_state = {"key1": "value1", "timestamp": "2025-01-01T12:00:00Z"}
        incoming_state = {"key1": "value2", "timestamp": "2025-01-01T12:01:00Z"}

        # Sync state
        self.sync_manager.sync_state(state_id, local_state)
        synced_state = self.sync_manager.retrieve_synced_state(state_id)

        # Assertions
        self.assertEqual(synced_state, local_state)

        # Resolve conflict
        resolved_state = self.sync_manager.resolve_conflicts(state_id, incoming_state)
        self.assertEqual(resolved_state["key1"], "value2")  # Latest timestamp wins

    def test_monitoring_service(self):
        """
        Tests performance monitoring and alert generation.
        """
        # Mock metrics and thresholds
        component_id = "test_component_001"
        self.monitoring_service.update_metrics(component_id, {"CPU": 85.0, "Memory": 65.0})
        self.monitoring_service.set_alert_thresholds(component_id, {"CPU": 80.0})

        # Monitoring request
        request = MonitoringRequest(component_id=component_id, metrics=["CPU", "Memory"])
        response = self.monitoring_service.monitor(request)

        # Assertions
        self.assertEqual(response.component_id, component_id)
        self.assertIn("CPU", response.performance_metrics)
        self.assertIn("alert_messages", response)
        self.assertIn("CPU exceeded threshold", response.alert_messages["CPU"])

    def test_scalability(self):
        """
        Stress-tests the system with a large number of tasks and data points.
        """
        large_data = [
            {"id": str(i), "value": i, "timestamp": datetime.utcnow().isoformat()}
            for i in range(10000)
        ]
        processed_data = self.preprocessor.preprocess(large_data)

        # Assertions
        self.assertEqual(len(processed_data), 10000)

        # Simulate task execution
        tasks = [
            NoesisTask(
                task_id=f"task_{i}",
                task_type=1,  # TASK_TRAINING
                data_sources=["source"],
                task_metadata={},
            )
            for i in range(1000)
        ]

        for task in tasks:
            result = self.task_executor.execute(task)
            self.assertEqual(result.outcome, TaskOutcome.TASK_SUCCESS)

    def test_export_import_configs(self):
        """
        Validates the ability to export and import configurations dynamically.
        """
        from src.noesis.config_manager import ConfigManager

        config_manager = ConfigManager()
        config_manager.load_from_seigr("test_component", self.test_config)
        exported_config = config_manager.export_to_dict("test_component")

        # Assertions
        self.assertIn("config_id", exported_config)
        self.assertEqual(exported_config["config_id"], "test_config_001")
