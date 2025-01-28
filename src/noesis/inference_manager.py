import logging
from typing import Dict, Any, Tuple, List
from datetime import datetime, timezone
from src.seigr_protocol.compiled.noesis_pb2 import (
    NoesisTask,
    TaskResult,
    IntermediateMetrics,
)
from src.logger.secure_logger import secure_logger
from src.dot_seigr.seigr_file import SeigrFile

# Initialize logger
logger = logging.getLogger(__name__)


class InferenceManager:
    """
    Manages inference tasks for Noesis, including model selection, data routing,
    and results aggregation in alignment with Seigr's Noesis principles.
    """

    def __init__(self):
        """
        Initializes the InferenceManager with an in-memory model registry and state.
        """
        self.active_models: Dict[str, Any] = {}  # In-memory model registry
        logger.info("InferenceManager initialized successfully.")

    def register_model(self, model_id: str, model: Any) -> None:
        """
        Registers a model for inference.

        Args:
            model_id (str): Unique identifier for the model.
            model (Any): The model object to be used for inference.
        """
        if model_id in self.active_models:
            logger.warning(f"Model with ID {model_id} is already registered.")
        else:
            self.active_models[model_id] = model
            logger.info(f"Model registered with ID: {model_id}")

    def execute_inference(self, request: NoesisTask) -> TaskResult:
        """
        Executes an inference task based on the provided request.

        Args:
            request (NoesisTask): The inference task request.

        Returns:
            TaskResult: The result of the inference task.
        """
        try:
            logger.info(f"Starting inference task with ID: {request.task_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Inference",
                message=f"Inference task started with ID: {request.task_id}",
                sensitive=False,
            )

            # Validate the request
            self._validate_request(request)

            # Retrieve the model
            model = self._get_model(request.related_model_ids[0])

            # Prepare input data from .seigr files
            input_data = self._load_data_from_seigr_files(request.data_sources)

            # Execute the inference
            result, metrics = self._run_inference(model, input_data)

            # Log success
            logger.info(f"Inference task completed successfully for ID: {request.task_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Inference",
                message=f"Inference task completed for ID: {request.task_id}",
                sensitive=False,
            )

            # Return the task result
            return TaskResult(
                task_id=request.task_id,
                outcome=1,  # TASK_SUCCESS
                message="Inference completed successfully.",
                result_metadata={"result": result, "metrics": metrics},
            )

        except Exception as e:
            logger.error(f"Inference task failed for ID {request.task_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Inference",
                message=f"Inference task failed for ID: {request.task_id}: {e}",
                sensitive=True,
            )
            return TaskResult(
                task_id=request.task_id,
                outcome=2,  # TASK_FAILURE
                message=f"Inference failed: {e}",
            )

    def _validate_request(self, request: NoesisTask) -> None:
        """
        Validates the inference task request.

        Args:
            request (NoesisTask): The request to validate.

        Raises:
            ValueError: If the request is invalid.
        """
        if not request.related_model_ids:
            raise ValueError("At least one model ID must be specified for inference.")
        if not request.data_sources:
            raise ValueError("Data sources are required for inference.")
        logger.debug("Inference request validated successfully.")

    def _get_model(self, model_id: str) -> Any:
        """
        Retrieves the model by its ID.

        Args:
            model_id (str): The ID of the model to retrieve.

        Returns:
            Any: The model object.

        Raises:
            ValueError: If the model is not found.
        """
        if model_id not in self.active_models:
            raise ValueError(f"Model with ID {model_id} not found.")
        logger.debug(f"Model with ID {model_id} retrieved successfully.")
        return self.active_models[model_id]

    def _load_data_from_seigr_files(self, seigr_file_paths: List[str]) -> Dict[str, Any]:
        """
        Loads and prepares input data for inference from `.seigr` files.

        Args:
            seigr_file_paths (list): List of paths to `.seigr` files.

        Returns:
            dict: Prepared data extracted from the `.seigr` files.
        """
        input_data = {}
        for file_path in seigr_file_paths:
            try:
                logger.debug(f"Loading data from .seigr file: {file_path}")
                seigr_file = SeigrFile.load(file_path)  # Load the Seigr capsule
                data = seigr_file.extract_inference_data()  # Extract relevant inference data
                input_data[file_path] = data
                logger.debug(f"Successfully extracted data from: {file_path}")
            except Exception as e:
                logger.error(f"Error processing .seigr file {file_path}: {e}")
                raise ValueError(f"Failed to process .seigr file {file_path}")
        return input_data

    def _run_inference(
        self, model: Any, input_data: Dict[str, Any]
    ) -> Tuple[Any, Dict[str, float]]:
        """
        Executes the inference process.

        Args:
            model (Any): The model to use for inference.
            input_data (dict): The prepared input data.

        Returns:
            tuple: The inference result and metrics.
        """
        logger.info("Running inference process.")
        if not hasattr(model, "predict"):
            raise ValueError("The provided model does not support the `predict` method.")
        result = model.predict(input_data)
        metrics = self._generate_metrics(result)
        logger.debug(f"Inference result: {result}, metrics: {metrics}")
        return result, metrics

    def _generate_metrics(self, result: Any) -> Dict[str, float]:
        """
        Generates metrics from the inference result.

        Args:
            result (Any): The inference result.

        Returns:
            dict: Metrics derived from the result.
        """
        logger.debug("Generating metrics from inference result.")
        return {
            "accuracy": result.get("accuracy", 0.0),
            "processing_time": result.get("time_elapsed", 0.0),
        }
