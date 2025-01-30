import logging
from typing import Dict, List, Any
from datetime import datetime, timezone
from threading import Lock

from google.protobuf.timestamp_pb2 import Timestamp
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
        self.lock = Lock()
        logger.info("✅ MonitoringService initialized successfully.")

    def monitor(self, request: MonitoringRequest) -> NoesisMonitoring:
        """
        Handles the MonitorNoesis RPC call to track performance metrics.
        """
        try:
            component_id = request.component_id
            metrics_to_monitor = request.metrics

            logger.info(f"🔍 Monitoring started for component: {component_id}")

            if not self.lock.acquire(timeout=5):
                logger.error(f"🚨 Deadlock detected! Unable to acquire lock in `monitor()` for {component_id}")
                return NoesisMonitoring(
                    component_id=component_id,
                    current_state=NoesisState.NOESIS_ERROR,
                    last_updated="LOCK_TIMEOUT",
                    performance_metrics={},
                    alert_thresholds={},
                    alert_messages={"error": "Lock acquisition timeout"},
                )

            try:
                if component_id not in self.metrics:
                    raise ValueError(f"Component {component_id} not found.")

                component_metrics = self.metrics.get(component_id, {}).copy()

            finally:
                self.lock.release()

            alerts = self._check_alerts_unlocked(component_id, component_metrics)
            current_state = self._determine_state(component_metrics)
            self._log_historical_metrics_unlocked(component_id, component_metrics)

            # ✅ Strict enforcement of `datetime`
            timestamp_value = datetime.now(timezone.utc)
            
            logger.debug(f"🔍 Raw timestamp before conversion: {timestamp_value} (type: {type(timestamp_value).__name__})")

            if isinstance(timestamp_value, str):
                logger.warning(f"⚠️ WARNING: Fixing timestamp string conversion.")
                timestamp_value = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))

            if not isinstance(timestamp_value, datetime):
                raise TypeError(f"❌ ERROR: Invalid timestamp type `{type(timestamp_value).__name__}`, expected `datetime`.")

            # ✅ Convert `datetime` to Protobuf `Timestamp`
            timestamp_proto = Timestamp()
            timestamp_proto.FromDatetime(timestamp_value)

            logger.debug(f"✅ Converted to Protobuf Timestamp: {timestamp_proto} (type: {type(timestamp_proto)})")

            monitoring_response = NoesisMonitoring(
                component_id=component_id,
                current_state=current_state,
                last_updated=timestamp_proto,  # ✅ Pass Timestamp directly
                performance_metrics=component_metrics,
                alert_thresholds=self.alert_thresholds.get(component_id, {}),
                alert_messages=alerts,
            )

            logger.info(f"✅ Monitoring completed for component: {component_id}")

            secure_logger.log_audit_event(
                severity=1,
                category="Monitoring",
                message=f"Monitoring completed for component: {component_id}",
                sensitive=False,
            )

            return monitoring_response

        except Exception as e:
            logger.error(f"❌ Monitoring failed for component {request.component_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Monitoring",
                message=f"Monitoring failure for component {request.component_id}: {e}",
                sensitive=True,
            )
            raise

    def _check_alerts_unlocked(
        self, component_id: str, metrics: Dict[str, float]
    ) -> Dict[str, str]:
        """
        Checks for alerts WITHOUT acquiring self.lock.
        """
        logger.debug(f"🔎 Checking alerts for component: {component_id}")
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

    def _log_historical_metrics_unlocked(
        self, component_id: str, metrics: Dict[str, float]
    ) -> None:
        """
        Logs historical metrics WITHOUT acquiring self.lock.
        """
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        # ✅ No lock acquisition here
        if component_id not in self.historical_metrics:
            self.historical_metrics[component_id] = []
        self.historical_metrics[component_id].append(
            {"timestamp": timestamp_proto.ToJsonString(), "metrics": metrics}
        )

        logger.debug(f"📜 Historical metrics logged for component: {component_id}")

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
        logger.debug(f"🔍 Fetching metrics for component: {component_id}")

        if not self.lock.acquire(timeout=5):
            logger.error(f"🚨 Deadlock detected! Unable to acquire lock for {component_id}.")
            return {}

        try:
            all_metrics = self.metrics.get(component_id, {})
        finally:
            self.lock.release()  # ✅ Always release lock
            logger.debug(f"✅ Lock released after fetching metrics for {component_id}")

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
        logger.debug(f"🔎 Entering _check_alerts for component: {component_id}")

        # 🔥 Debug before acquiring the lock
        logger.debug(
            f"⏳ Attempting to acquire lock in _check_alerts for component: {component_id}"
        )

        with self.lock:
            logger.debug(f"✅ Lock acquired in _check_alerts for component: {component_id}")
            thresholds = self.alert_thresholds.get(component_id, {})

            alerts = {}
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

            logger.debug(f"🔓 Releasing lock in _check_alerts for component: {component_id}")

        logger.debug(f"🚀 Exiting _check_alerts for component: {component_id}")
        return alerts

    def _determine_state(self, metrics: Dict[str, float]) -> NoesisState:
        """
        Determines the operational state of a component based on its metrics.

        Args:
            metrics (dict): Current metrics for the component.

        Returns:
            NoesisState: Operational state of the component.
        """
        logger.debug("🔍 Determining operational state from metrics.")
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
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        with self.lock:
            if component_id not in self.historical_metrics:
                self.historical_metrics[component_id] = []
            self.historical_metrics[component_id].append(
                {"timestamp": timestamp_proto.ToJsonString(), "metrics": metrics}
            )
        logger.debug(f"✅ Historical metrics logged for component: {component_id}")

    def update_metrics(self, component_id: str, new_metrics: Dict[str, float]) -> None:
        """
        Updates the performance metrics for a specific component.
        """
        with self.lock:
            self.metrics[component_id] = new_metrics
        logger.info(f"🔄 Updating metrics for component: {component_id}")

    def set_alert_thresholds(self, component_id: str, thresholds: Dict[str, float]) -> None:
        """
        Sets alert thresholds for a component.
        """
        with self.lock:
            self.alert_thresholds[component_id] = thresholds
        logger.info(f"🔄 Setting alert thresholds for component: {component_id}")
