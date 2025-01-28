import logging
from typing import Dict, List, Any
from datetime import datetime, timezone
from src.seigr_protocol.compiled.noesis_pb2 import (
    MonitoringRequest,
    NoesisMonitoring,
    NoesisState,
)
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)


class MonitoringService:
    """
    Provides performance monitoring for Noesis components, including
    real-time metrics tracking, alert generation, and state management.
    """

    def __init__(self):
        """
        Initializes the MonitoringService with in-memory storage for metrics and thresholds.
        """
        self.metrics: Dict[str, Dict[str, float]] = {}
        self.alert_thresholds: Dict[str, Dict[str, float]] = {}
        self.historical_metrics: Dict[str, List[Dict[str, Any]]] = {}
        logger.info("MonitoringService initialized successfully.")

    def monitor(self, request: MonitoringRequest) -> NoesisMonitoring:
        """
        Handles the MonitorNoesis RPC call to track performance metrics.

        Args:
            request (MonitoringRequest): The monitoring request specifying component ID and metrics.

        Returns:
            NoesisMonitoring: The monitoring response containing metrics, state, and alerts.
        """
        try:
            component_id = request.component_id
            metrics_to_monitor = request.metrics

            logger.info(f"Monitoring initiated for component: {component_id}")
            if component_id not in self.metrics:
                raise ValueError(f"Component {component_id} not found.")

            # Retrieve component metrics
            component_metrics = self._get_component_metrics(component_id, metrics_to_monitor)

            # Generate alerts if thresholds are breached
            alerts = self._check_alerts(component_id, component_metrics)

            # Determine the current operational state of the component
            current_state = self._determine_state(component_metrics)

            # Save metrics to historical data
            self._log_historical_metrics(component_id, component_metrics)

            # Construct monitoring response
            monitoring_response = NoesisMonitoring(
                component_id=component_id,
                current_state=current_state,
                last_updated=datetime.now(timezone.utc).isoformat(),  # Updated to timezone-aware
                performance_metrics=component_metrics,
                alert_thresholds=self.alert_thresholds.get(component_id, {}),
                alert_messages=alerts,
            )

            logger.info(f"Monitoring completed for component: {component_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Monitoring",
                message=f"Monitoring completed for component: {component_id}",
                sensitive=False,
            )
            return monitoring_response

        except Exception as e:
            logger.error(f"Monitoring failed for component {request.component_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Monitoring",
                message=f"Monitoring failure for component {request.component_id}: {e}",
                sensitive=True,
            )
            raise

    def _get_component_metrics(
        self, component_id: str, metrics_to_monitor: List[str]
    ) -> Dict[str, float]:
        """
        Retrieves specified metrics for a component.

        Args:
            component_id (str): The component ID.
            metrics_to_monitor (list): List of metrics to retrieve.

        Returns:
            dict: Dictionary of requested metrics and their values.
        """
        logger.debug(f"Fetching metrics for component: {component_id}")
        all_metrics = self.metrics.get(component_id, {})
        return {metric: all_metrics.get(metric, 0.0) for metric in metrics_to_monitor}

    def _check_alerts(self, component_id: str, metrics: Dict[str, float]) -> Dict[str, str]:
        """
        Compares metrics against alert thresholds to generate alerts.

        Args:
            component_id (str): The component ID.
            metrics (dict): Current metrics for the component.

        Returns:
            dict: Dictionary of alert messages for breached thresholds.
        """
        logger.debug(f"Checking alerts for component: {component_id}")
        alerts = {}
        thresholds = self.alert_thresholds.get(component_id, {})

        for metric, value in metrics.items():
            if metric in thresholds and value > thresholds[metric]:
                alert_message = f"{metric} exceeded threshold: {value} > {thresholds[metric]}"
                alerts[metric] = alert_message
                logger.warning(alert_message)
                secure_logger.log_audit_event(
                    severity=2,
                    category="Monitoring",
                    message=alert_message,
                    sensitive=False,
                )

        return alerts

    def _determine_state(self, metrics: Dict[str, float]) -> NoesisState:
        """
        Determines the operational state of a component based on its metrics.

        Args:
            metrics (dict): Current metrics for the component.

        Returns:
            NoesisState: Operational state of the component.
        """
        logger.debug("Determining operational state from metrics.")
        if any(value > 90.0 for value in metrics.values()):
            return NoesisState.NOESIS_DEGRADED
        elif all(value < 50.0 for value in metrics.values()):
            return NoesisState.NOESIS_ACTIVE
        else:
            return NoesisState.NOESIS_INITIALIZING

    def _log_historical_metrics(self, component_id: str, metrics: Dict[str, float]) -> None:
        """
        Logs current metrics into historical storage.

        Args:
            component_id (str): The component ID.
            metrics (dict): Current metrics to log.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        if component_id not in self.historical_metrics:
            self.historical_metrics[component_id] = []
        self.historical_metrics[component_id].append({"timestamp": timestamp, "metrics": metrics})
        logger.debug(f"Historical metrics logged for component: {component_id}")

    def update_metrics(self, component_id: str, new_metrics: Dict[str, float]) -> None:
        """
        Updates the performance metrics for a specific component.

        Args:
            component_id (str): The component ID.
            new_metrics (dict): Dictionary of updated metrics.
        """
        logger.info(f"Updating metrics for component: {component_id}")
        self.metrics[component_id] = new_metrics
        secure_logger.log_audit_event(
            severity=1,
            category="Monitoring",
            message=f"Metrics updated for component: {component_id}",
            sensitive=False,
        )

    def set_alert_thresholds(self, component_id: str, thresholds: Dict[str, float]) -> None:
        """
        Sets alert thresholds for a component.

        Args:
            component_id (str): The component ID.
            thresholds (dict): Dictionary of metric thresholds.
        """
        logger.info(f"Setting alert thresholds for component: {component_id}")
        self.alert_thresholds[component_id] = thresholds
        secure_logger.log_audit_event(
            severity=1,
            category="Monitoring",
            message=f"Alert thresholds set for component: {component_id}",
            sensitive=False,
        )

    def reset_component_metrics(self, component_id: str) -> None:
        """
        Resets metrics and thresholds for a specific component.

        Args:
            component_id (str): The component ID to reset.
        """
        if component_id in self.metrics:
            del self.metrics[component_id]
        if component_id in self.alert_thresholds:
            del self.alert_thresholds[component_id]
        logger.info(f"Metrics and thresholds reset for component: {component_id}")

    def get_all_metrics(self) -> Dict[str, Dict[str, float]]:
        """
        Retrieves metrics for all components.

        Returns:
            dict: All metrics currently tracked.
        """
        logger.info("Fetching all metrics for monitored components.")
        return self.metrics
