import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class NoesisVisualizer:
    """
    Provides visualization tools for Noesis system states, tasks, and interactions,
    outputting data in a custom format that aligns with Seigr's principles.
    """

    def __init__(self):
        """
        Initializes the NoesisVisualizer with a simple internal representation.
        """
        self.state_network = {}
        self.task_distribution = {}
        self.performance_metrics = {}
        logger.info("NoesisVisualizer initialized successfully.")

    def visualize_state_network(self, state_data: List[Dict[str, Any]]):
        """
        Generates a custom representation of the interconnected network of Noesis states.

        Args:
            state_data (List[Dict[str, Any]]): List of states with connection information.
        """
        logger.info("Generating state network visualization.")
        try:
            # Validate input
            self._validate_state_data(state_data)

            # Build the network
            self.state_network = {state["id"]: state["hash_routes"] for state in state_data}

            # Serialize to a custom Seigr format
            visualization_data = self._serialize_network(self.state_network)
            self._save_visualization("state_network", visualization_data)

            logger.info("State network visualization generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate state network visualization: {e}")

    def visualize_task_distribution(self, task_data: List[Dict[str, Any]]):
        """
        Generates a custom representation of task distribution.

        Args:
            task_data (List[Dict[str, Any]]): List of tasks with metadata.
        """
        logger.info("Generating task distribution visualization.")
        try:
            # Validate input
            self._validate_task_data(task_data)

            # Aggregate tasks by type
            for task in task_data:
                task_type = task.get("task_type", "Undefined")
                self.task_distribution[task_type] = self.task_distribution.get(task_type, 0) + 1

            # Serialize to a custom Seigr format
            visualization_data = self._serialize_task_distribution(self.task_distribution)
            self._save_visualization("task_distribution", visualization_data)

            logger.info("Task distribution visualization generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate task distribution visualization: {e}")

    def visualize_performance_metrics(self, metrics: Dict[str, float]):
        """
        Generates a custom representation of performance metrics.

        Args:
            metrics (Dict[str, float]): Dictionary of metric names and values.
        """
        logger.info("Generating performance metrics visualization.")
        try:
            # Validate input
            self._validate_metrics(metrics)

            self.performance_metrics = metrics

            # Serialize to a custom Seigr format
            visualization_data = self._serialize_metrics(metrics)
            self._save_visualization("performance_metrics", visualization_data)

            logger.info("Performance metrics visualization generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate performance metrics visualization: {e}")

    def _validate_state_data(self, state_data: List[Dict[str, Any]]):
        """
        Validates state data for correctness.

        Args:
            state_data (List[Dict[str, Any]]): The state data to validate.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(state_data, list):
            raise ValueError("State data must be a list of dictionaries.")
        for state in state_data:
            if "id" not in state or "hash_routes" not in state:
                raise ValueError("Each state must contain 'id' and 'hash_routes' keys.")

    def _validate_task_data(self, task_data: List[Dict[str, Any]]):
        """
        Validates task data for correctness.

        Args:
            task_data (List[Dict[str, Any]]): The task data to validate.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(task_data, list):
            raise ValueError("Task data must be a list of dictionaries.")
        for task in task_data:
            if "task_type" not in task:
                raise ValueError("Each task must contain a 'task_type' key.")

    def _validate_metrics(self, metrics: Dict[str, float]):
        """
        Validates metrics data for correctness.

        Args:
            metrics (Dict[str, float]): The metrics to validate.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(metrics, dict):
            raise ValueError("Metrics must be a dictionary with string keys and float values.")
        for key, value in metrics.items():
            if not isinstance(value, (float, int)):
                raise ValueError(f"Metric '{key}' must have a numeric value.")

    def _serialize_network(self, network: Dict[str, Dict[str, float]]) -> str:
        """
        Serializes a network into a custom Seigr-compatible format.

        Args:
            network (dict): Network data.

        Returns:
            str: Serialized network representation.
        """
        serialized = f"StateNetwork | Generated on {datetime.utcnow().isoformat()}\n"
        for node, edges in network.items():
            serialized += f"{node} -> {', '.join(f'{target} ({weight})' for target, weight in edges.items())}\n"
        return serialized

    def _serialize_task_distribution(self, distribution: Dict[str, int]) -> str:
        """
        Serializes task distribution data into a custom Seigr-compatible format.

        Args:
            distribution (dict): Task distribution data.

        Returns:
            str: Serialized distribution representation.
        """
        serialized = f"TaskDistribution | Generated on {datetime.utcnow().isoformat()}\n"
        for task_type, count in distribution.items():
            serialized += f"{task_type}: {count}\n"
        return serialized

    def _serialize_metrics(self, metrics: Dict[str, float]) -> str:
        """
        Serializes performance metrics into a custom Seigr-compatible format.

        Args:
            metrics (dict): Metrics data.

        Returns:
            str: Serialized metrics representation.
        """
        serialized = f"PerformanceMetrics | Generated on {datetime.utcnow().isoformat()}\n"
        for metric, value in metrics.items():
            serialized += f"{metric}: {value}\n"
        return serialized

    def _save_visualization(self, name: str, data: str):
        """
        Saves visualization data to a custom Seigr-compatible file.

        Args:
            name (str): Visualization name.
            data (str): Serialized data.
        """
        filename = f"{name}.seigrviz"
        try:
            with open(filename, "w") as file:
                file.write(data)
            logger.info(f"Visualization saved as {filename}.")
        except Exception as e:
            logger.error(f"Failed to save visualization {name}: {e}")
