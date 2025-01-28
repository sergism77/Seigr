import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from threading import Lock
import numpy as np

# Initialize logger
logger = logging.getLogger(__name__)


class TrainingManager:
    """
    Handles adaptive training tasks within the Noesis system, enabling emergent intelligence
    and evolution of .seigr files via the Base-6 framework.

    Attributes:
        model_states (dict): Tracks the states of models being trained.
        lock (Lock): Thread-safe mechanism for managing model states.
    """

    def __init__(self):
        """
        Initializes the TrainingManager and its internal state.
        """
        self.model_states: Dict[str, Dict[str, Any]] = {}
        self.lock = Lock()  # Thread-safe state management
        logger.info("TrainingManager initialized successfully.")

    def execute_training(
        self, genesis_state: Dict[str, Any], feedback: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Executes adaptive training on a .seigr file's internal state.

        Args:
            genesis_state (Dict[str, Any]): Initial state of the .seigr file's learning engine.
            feedback (List[Dict[str, Any]]): Feedback from Hyphens or environmental data.

        Returns:
            Dict[str, Any]: Updated state and training metrics.
        """
        try:
            logger.info(f"Starting training for genesis state: {genesis_state['name']}")

            # Validate and initialize
            self._validate_genesis_state(genesis_state)
            current_state = self._initialize_state(genesis_state)

            # Incorporate feedback
            feedback_weight = self._integrate_feedback(feedback, current_state)

            # Perform adaptive learning
            metrics = self._adaptive_learning_cycle(current_state, feedback_weight)

            # Update genesis state with new internal state and history
            self._update_genesis_state(genesis_state, current_state, metrics)

            logger.info(f"Training completed for state: {genesis_state['name']}")
            return {
                "updated_state": genesis_state,
                "training_metrics": metrics,
            }

        except Exception as e:
            logger.error(f"Training failed for genesis state: {e}")
            raise RuntimeError(f"Training failed: {e}") from e

    def _validate_genesis_state(self, genesis_state: Dict[str, Any]):
        """
        Validates the structure and fields of the genesis state.

        Args:
            genesis_state (Dict[str, Any]): Genesis state of the .seigr file.

        Raises:
            ValueError: If validation fails.
        """
        required_fields = ["name", "ml_engine", "hash_routes", "history"]
        for field in required_fields:
            if field not in genesis_state:
                raise ValueError(f"Missing required field in genesis state: {field}")
        logger.debug(f"Genesis state validated: {genesis_state['name']}")

    def _initialize_state(self, genesis_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initializes the internal state of the learning engine.

        Args:
            genesis_state (Dict[str, Any]): Genesis state of the .seigr file.

        Returns:
            Dict[str, Any]: Initialized internal state.
        """
        internal_state = genesis_state["ml_engine"].get("internal_state", [0.0] * 6)
        rules = genesis_state["ml_engine"].get("rules", [])
        initialized_state = {"internal_state": internal_state, "rules": rules}
        logger.debug(f"Initialized internal state: {initialized_state}")
        return initialized_state

    def _integrate_feedback(
        self, feedback: List[Dict[str, Any]], current_state: Dict[str, Any]
    ) -> float:
        """
        Integrates Hyphen and environmental feedback into the learning process.

        Args:
            feedback (List[Dict[str, Any]]): Feedback data.
            current_state (Dict[str, Any]): Current internal state of the learning engine.

        Returns:
            float: Aggregated feedback weight for learning adjustments.
        """
        total_impact = sum(item.get("impact", 0.0) for item in feedback)
        for item in feedback:
            if "content" in item:
                current_state["rules"].append(f"Feedback: {item['content']}")
        logger.debug(f"Integrated feedback with total impact: {total_impact}")
        return total_impact

    def _adaptive_learning_cycle(
        self, current_state: Dict[str, Any], feedback_weight: float
    ) -> Dict[str, Any]:
        """
        Executes an adaptive learning cycle, evolving the internal state and generating new rules.

        Args:
            current_state (Dict[str, Any]): Current internal state.
            feedback_weight (float): Weight of integrated feedback.

        Returns:
            Dict[str, Any]: Training metrics, including convergence and stability metrics.
        """
        logger.debug("Starting adaptive learning cycle.")
        initial_state = np.array(current_state["internal_state"])
        feedback_adjustment = feedback_weight * 0.1

        # Update internal state dynamically
        current_state["internal_state"] = list(initial_state + feedback_adjustment)
        rule_change_magnitude = np.linalg.norm(
            initial_state - np.array(current_state["internal_state"])
        )

        # Add a new rule
        new_rule = f"Rule_{len(current_state['rules']) + 1}: Feedback_Weight_{feedback_weight:.2f}"
        current_state["rules"].append(new_rule)

        # Training Metrics
        metrics = {
            "rule_change_magnitude": rule_change_magnitude,
            "feedback_weight": feedback_weight,
            "state_convergence": float(np.mean(current_state["internal_state"])),
        }

        logger.debug(f"Learning cycle completed with metrics: {metrics}")
        return metrics

    def _update_genesis_state(
        self, genesis_state: Dict[str, Any], current_state: Dict[str, Any], metrics: Dict[str, Any]
    ):
        """
        Updates the genesis state with new internal state, rules, and history.

        Args:
            genesis_state (Dict[str, Any]): Original genesis state.
            current_state (Dict[str, Any]): Updated internal state and rules.
            metrics (Dict[str, Any]): Metrics from the training cycle.
        """
        genesis_state["ml_engine"]["internal_state"] = current_state["internal_state"]
        genesis_state["ml_engine"]["rules"] = current_state["rules"]
        genesis_state["history"].append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": "Training cycle completed.",
                "metrics": metrics,
            }
        )
        logger.debug(f"Genesis state updated with new training metrics: {metrics}")
