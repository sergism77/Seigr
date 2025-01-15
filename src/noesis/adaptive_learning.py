import logging
from typing import Dict, List
from datetime import datetime
from src.seigr_protocol.compiled.noesis_pb2 import (
    AdaptiveLearning,
    LearningResult,
    IntermediateMetrics,
)
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)

class AdaptiveLearningManager:
    """
    Manages adaptive learning processes, enabling emergent intelligence
    and tracking performance improvements across .seigr files.
    """

    def __init__(self):
        """
        Initializes the AdaptiveLearningManager.
        """
        self.lineage_tracker: Dict[str, List[Dict[str, float]]] = {}
        logger.info("AdaptiveLearningManager initialized successfully.")

    def start_learning(self, request: AdaptiveLearning) -> LearningResult:
        """
        Starts an adaptive learning process based on the provided request.

        Args:
            request (AdaptiveLearning): The adaptive learning request.

        Returns:
            LearningResult: The result of the adaptive learning process.
        """
        try:
            logger.info(f"Starting adaptive learning for model ID: {request.model_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="AdaptiveLearning",
                message=f"Starting adaptive learning for process ID: {request.process_id}",
                sensitive=False,
            )

            # Validate the request
            self._validate_request(request)

            # Execute adaptive learning
            tuned_params, intermediate_metrics = self._adaptive_learning_cycle(
                request.initial_parameters,
                request.tuning_strategy,
                request.stopping_criteria,
            )

            # Track lineage
            self._track_lineage(request.model_id, tuned_params)

            # Calculate performance improvement
            improvement_score = self._calculate_improvement_score(
                request.initial_parameters, tuned_params
            )

            # Log success
            logger.info(f"Adaptive learning completed successfully for process ID: {request.process_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="AdaptiveLearning",
                message=f"Adaptive learning completed successfully for process ID: {request.process_id}",
                sensitive=False,
            )

            # Create and return the result
            return LearningResult(
                process_id=request.process_id,
                success=True,
                improvement_score=improvement_score,
                message="Adaptive learning completed successfully.",
                intermediate_metrics=intermediate_metrics,
            )

        except Exception as e:
            # Log failure
            logger.error(f"Adaptive learning failed for process ID {request.process_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="AdaptiveLearning",
                message=f"Adaptive learning failed for process ID: {request.process_id}: {e}",
                sensitive=True,
            )
            return LearningResult(
                process_id=request.process_id,
                success=False,
                improvement_score=0.0,
                message=f"Adaptive learning failed: {e}",
            )

    def _validate_request(self, request: AdaptiveLearning):
        """
        Validates the adaptive learning request.

        Args:
            request (AdaptiveLearning): The request to validate.

        Raises:
            ValueError: If the request is invalid.
        """
        if not request.model_id:
            raise ValueError("Model ID is required for adaptive learning.")
        if not request.tuning_strategy:
            raise ValueError("Tuning strategy must be specified.")
        if not request.initial_parameters:
            raise ValueError("Initial parameters are required.")
        logger.debug("Adaptive learning request validated successfully.")

    def _adaptive_learning_cycle(
        self, initial_params: Dict[str, float], strategy: str, stopping_criteria: Dict[str, float]
    ) -> tuple[Dict[str, float], List[IntermediateMetrics]]:
        """
        Executes an adaptive learning cycle, evolving the internal parameters
        based on the specified strategy.

        Args:
            initial_params (dict): Initial hyperparameters.
            strategy (str): Tuning strategy (e.g., emergent grid, probabilistic adjustments).
            stopping_criteria (dict): Criteria for stopping (e.g., max iterations).

        Returns:
            tuple: Tuned parameters and intermediate metrics.
        """
        logger.info(f"Starting adaptive learning with strategy: {strategy}")
        tuned_params = initial_params.copy()
        intermediate_metrics = []

        # Adaptive learning iterations
        max_iterations = int(stopping_criteria.get("max_iterations", 10))
        target_score = stopping_criteria.get("target_score", 0.9)

        for iteration in range(max_iterations):
            # Adjust parameters based on emergent strategy
            tuned_params = {
                key: value + (iteration * 0.05) for key, value in tuned_params.items()
            }
            metrics = {
                "iteration": iteration,
                "performance_score": sum(tuned_params.values()) / len(tuned_params),
            }

            # Track intermediate metrics
            intermediate_metrics.append(
                IntermediateMetrics(
                    metrics=metrics,
                    timestamp=datetime.utcnow().isoformat(),
                )
            )

            # Check stopping criteria
            if metrics["performance_score"] >= target_score:
                logger.info("Target performance score achieved.")
                break

        return tuned_params, intermediate_metrics

    def _calculate_improvement_score(
        self, initial_params: Dict[str, float], tuned_params: Dict[str, float]
    ) -> float:
        """
        Calculates the improvement score for the learning process.

        Args:
            initial_params (dict): Initial parameters.
            tuned_params (dict): Tuned parameters.

        Returns:
            float: The improvement score.
        """
        initial_score = sum(initial_params.values())
        tuned_score = sum(tuned_params.values())
        improvement = (tuned_score - initial_score) / max(initial_score, 1e-6)
        logger.debug(f"Calculated improvement score: {improvement}")
        return improvement

    def _track_lineage(self, model_id: str, tuned_params: Dict[str, float]):
        """
        Tracks the lineage of parameter evolution.

        Args:
            model_id (str): The unique identifier of the model.
            tuned_params (dict): The updated parameters to track.
        """
        timestamp = datetime.utcnow().isoformat()
        if model_id not in self.lineage_tracker:
            self.lineage_tracker[model_id] = []
        self.lineage_tracker[model_id].append({"timestamp": timestamp, "parameters": tuned_params})
        logger.info(f"Lineage updated for model ID: {model_id}")
