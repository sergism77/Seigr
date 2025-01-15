import logging
from typing import Dict, Any, List
from datetime import datetime
from src.noesis.training_manager import TrainingManager
from src.noesis.inference_manager import InferenceManager
from src.noesis.pipeline_manager import PipelineManager
from src.seigr_protocol.compiled.noesis_pb2 import (
    NoesisTask,
    TaskResult,
    TaskOutcome,
)
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)


class TaskExecutor:
    """
    Handles the execution of tasks in the Noesis system, including training,
    inference, and pipeline execution.

    Attributes:
        training_manager (TrainingManager): Manages training tasks.
        inference_manager (InferenceManager): Manages inference tasks.
        pipeline_manager (PipelineManager): Manages data pipelines.
        task_history (dict): Tracks the history of executed tasks.
    """

    def __init__(self):
        """
        Initializes the TaskExecutor with managers for each task type and
        a placeholder for ongoing tasks.
        """
        self.training_manager = TrainingManager()
        self.inference_manager = InferenceManager()
        self.pipeline_manager = PipelineManager()
        self.task_history: Dict[str, Dict[str, Any]] = {}
        logger.info("TaskExecutor initialized successfully.")

    def execute(self, task: NoesisTask) -> TaskResult:
        """
        Executes a given task based on its type.

        Args:
            task (NoesisTask): The task to be executed.

        Returns:
            TaskResult: The result of the task execution.
        """
        try:
            logger.info(f"Executing task with ID: {task.task_id} of type {task.task_type}")

            # Log the start time of the task
            start_time = datetime.utcnow()

            # Execute the task based on its type
            if task.task_type == 1:  # TASK_TRAINING
                result_metadata = self.training_manager.execute_training(task)
            elif task.task_type == 2:  # TASK_INFERENCE
                result_metadata = self.inference_manager.execute_inference(task)
            elif task.task_type == 3:  # TASK_PIPELINE_EXECUTION
                result_metadata = self.pipeline_manager.execute_pipeline(task)
            else:
                raise ValueError(f"Unsupported task type: {task.task_type}")

            # Log the end time of the task
            end_time = datetime.utcnow()

            # Save task history
            self._log_task_history(
                task_id=task.task_id,
                task_type=task.task_type,
                start_time=start_time,
                end_time=end_time,
                outcome=TaskOutcome.TASK_SUCCESS,
                metadata=result_metadata,
            )

            logger.info(f"Task with ID: {task.task_id} executed successfully.")
            return TaskResult(
                task_id=task.task_id,
                outcome=TaskOutcome.TASK_SUCCESS,
                message="Task executed successfully.",
                result_metadata=result_metadata,
            )

        except Exception as e:
            logger.error(f"Task execution failed for ID {task.task_id}: {e}")
            self._log_task_history(
                task_id=task.task_id,
                task_type=task.task_type,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                outcome=TaskOutcome.TASK_FAILURE,
                metadata={"error": str(e)},
            )
            secure_logger.log_audit_event(
                severity=4,
                category="TaskExecution",
                message=f"Task execution failed: {e}",
                sensitive=True,
            )
            return TaskResult(
                task_id=task.task_id,
                outcome=TaskOutcome.TASK_FAILURE,
                message=f"Task execution failed: {e}",
                result_metadata={"error": str(e)},
            )

    def _log_task_history(
        self,
        task_id: str,
        task_type: int,
        start_time: datetime,
        end_time: datetime,
        outcome: int,
        metadata: Dict[str, Any],
    ):
        """
        Logs task details to the task history.

        Args:
            task_id (str): Unique identifier of the task.
            task_type (int): Type of the task.
            start_time (datetime): Start time of the task.
            end_time (datetime): End time of the task.
            outcome (int): Outcome of the task.
            metadata (Dict[str, Any]): Additional metadata for the task.
        """
        self.task_history[task_id] = {
            "task_type": task_type,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "outcome": outcome,
            "metadata": metadata,
        }
        logger.debug(f"Task history updated for task ID: {task_id}")

    def get_task_history(self, initiated_by: str = None) -> List[Dict[str, Any]]:
        """
        Retrieves the task history, optionally filtering by the initiator.

        Args:
            initiated_by (str, optional): Filter tasks by their initiator.

        Returns:
            list: Task history data.
        """
        logger.info("Fetching task history")
        history = [
            {"task_id": task_id, **details}
            for task_id, details in self.task_history.items()
            if not initiated_by or details.get("metadata", {}).get("initiated_by") == initiated_by
        ]
        logger.info(f"Retrieved {len(history)} tasks from history.")
        return history
