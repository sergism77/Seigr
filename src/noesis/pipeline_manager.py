import logging
from typing import Dict, List, Any
from datetime import datetime
from src.seigr_protocol.compiled.noesis_pb2 import (
    NoesisTask,
    TaskResult,
    NoesisResponse,
    TaskOutcome,
)
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)

class PipelineManager:
    """
    Manages and orchestrates data pipelines for the Noesis module, enabling
    efficient and adaptive processing of inputs and outputs for various tasks.
    """

    def __init__(self):
        """
        Initializes the PipelineManager with in-memory state for pipelines.
        """
        self.active_pipelines: Dict[str, Dict[str, Any]] = {}
        logger.info("PipelineManager initialized successfully.")

    def create_pipeline(self, pipeline_id: str, config: Dict[str, Any]) -> NoesisResponse:
        """
        Creates a new data pipeline based on the provided configuration.

        Args:
            pipeline_id (str): Unique identifier for the pipeline.
            config (dict): Configuration details for the pipeline.

        Returns:
            NoesisResponse: Response indicating success or failure of the pipeline creation.
        """
        try:
            if pipeline_id in self.active_pipelines:
                raise ValueError(f"Pipeline with ID {pipeline_id} already exists.")

            self.active_pipelines[pipeline_id] = {
                "config": config,
                "status": "Initialized",
                "created_at": datetime.utcnow().isoformat(),
            }

            logger.info(f"Pipeline created with ID: {pipeline_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Pipeline",
                message=f"Pipeline created with ID: {pipeline_id}",
                sensitive=False,
            )
            return NoesisResponse(success=True, message="Pipeline created successfully.")
        except Exception as e:
            logger.error(f"Failed to create pipeline: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Pipeline",
                message=f"Failed to create pipeline: {e}",
                sensitive=True,
            )
            return NoesisResponse(success=False, message=f"Failed to create pipeline: {e}")


    def execute_pipeline(self, task: NoesisTask) -> TaskResult:
        """
        Executes a data pipeline based on the task request.

        Args:
            task (NoesisTask): The task containing the pipeline execution details.

        Returns:
            TaskResult: The result of the pipeline execution.
        """
        try:
            logger.info(f"Executing pipeline for task ID: {task.task_id}")
            pipeline_id = task.task_metadata.get("pipeline_id")
            if not pipeline_id or pipeline_id not in self.active_pipelines:
                raise ValueError(f"Pipeline ID {pipeline_id} not found.")

            pipeline = self.active_pipelines[pipeline_id]
            pipeline["status"] = "Running"
            pipeline["last_run"] = datetime.utcnow().isoformat()

            # Execute the pipeline logic
            processed_data = self._process_pipeline(task, pipeline)

            # Update pipeline status
            pipeline["status"] = "Completed"

            logger.info(f"Pipeline executed successfully for task ID: {task.task_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Pipeline",
                message=f"Pipeline executed successfully for task ID: {task.task_id}",
                sensitive=False,
            )
            return TaskResult(
                task_id=task.task_id,
                outcome=TaskOutcome.TASK_SUCCESS,
                message="Pipeline executed successfully.",
                result_metadata=processed_data,
            )
        except Exception as e:
            logger.error(f"Pipeline execution failed for task ID {task.task_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Pipeline",
                message=f"Pipeline execution failed for task ID {task.task_id}: {e}",
                sensitive=True,
            )
            return TaskResult(
                task_id=task.task_id,
                outcome=TaskOutcome.TASK_FAILURE,
                message=f"Pipeline execution failed: {e}",
            )


    def _process_pipeline(self, task: NoesisTask, pipeline: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes the pipeline task by invoking configured processing steps.

        Args:
            task (NoesisTask): Task containing the input data.
            pipeline (dict): Pipeline configuration and metadata.

        Returns:
            dict: Metadata containing results of the pipeline processing.
        """
        try:
            logger.debug(f"Processing pipeline for task ID: {task.task_id}")

            # Retrieve and simulate configured processing steps
            steps = pipeline["config"].get("steps", [])
            processed_metadata = {
                "task_id": task.task_id,
                "pipeline_id": pipeline["config"]["pipeline_id"],
                "steps": [],
            }

            for step in steps:
                try:
                    # Simulate execution of each step
                    step_result = f"Executed {step} for task {task.task_id}"
                    processed_metadata["steps"].append({"step": step, "result": step_result})
                    logger.debug(f"Step result: {step_result}")
                except Exception as step_error:
                    logger.error(f"Error executing step {step}: {step_error}")
                    processed_metadata["steps"].append({"step": step, "error": str(step_error)})

            return processed_metadata
        except Exception as e:
            logger.error(f"Error during pipeline processing: {e}")
            raise


    def update_pipeline(self, pipeline_id: str, updates: Dict[str, Any]) -> NoesisResponse:
        """
        Updates the configuration of an existing pipeline.

        Args:
            pipeline_id (str): Unique identifier for the pipeline.
            updates (dict): Configuration updates.

        Returns:
            NoesisResponse: Response indicating success or failure of the update.
        """
        try:
            if pipeline_id not in self.active_pipelines:
                raise ValueError(f"Pipeline with ID {pipeline_id} does not exist.")

            self.active_pipelines[pipeline_id]["config"].update(updates)
            logger.info(f"Pipeline {pipeline_id} updated successfully.")
            secure_logger.log_audit_event(
                severity=1,
                category="Pipeline",
                message=f"Pipeline {pipeline_id} updated successfully.",
                sensitive=False,
            )
            return NoesisResponse(success=True, message="Pipeline updated successfully.")
        except Exception as e:
            logger.error(f"Failed to update pipeline: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Pipeline",
                message=f"Failed to update pipeline: {e}",
                sensitive=True,
            )
            return NoesisResponse(success=False, message=f"Failed to update pipeline: {e}")


    def delete_pipeline(self, pipeline_id: str) -> NoesisResponse:
        """
        Deletes a pipeline and its associated configuration.

        Args:
            pipeline_id (str): Unique identifier for the pipeline.

        Returns:
            NoesisResponse: Response indicating success or failure of the deletion.
        """
        try:
            if pipeline_id not in self.active_pipelines:
                raise ValueError(f"Pipeline with ID {pipeline_id} does not exist.")

            del self.active_pipelines[pipeline_id]
            logger.info(f"Pipeline {pipeline_id} deleted successfully.")
            secure_logger.log_audit_event(
                severity=1,
                category="Pipeline",
                message=f"Pipeline {pipeline_id} deleted successfully.",
                sensitive=False,
            )
            return NoesisResponse(success=True, message="Pipeline deleted successfully.")
        except Exception as e:
            logger.error(f"Failed to delete pipeline: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Pipeline",
                message=f"Failed to delete pipeline: {e}",
                sensitive=True,
            )
            return NoesisResponse(success=False, message=f"Failed to delete pipeline: {e}")
