import logging
from typing import Dict, Any
from src.noesis.adaptive_learning import AdaptiveLearningManager
from src.noesis.task_executor import TaskExecutor
from src.noesis.monitoring import MonitoringService
from src.noesis.audit import AuditManager
from src.seigr_protocol.compiled.noesis_pb2 import (
    NoesisConfig,
    TaskResult,
    LearningResult,
    NoesisResponse,
    MonitoringRequest,
    AuditLogRequest,
    ConfigListResponse,
    TaskHistoryRequest,
    TaskHistoryResponse,
    NoesisTask,
    NoesisMonitoring,
)
from src.seigr_protocol.compiled.noesis_pb2_grpc import NoesisServiceServicer
import grpc
from threading import Lock
from limits import RateLimitItemPerMinute
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = FixedWindowRateLimiter(MemoryStorage())
rate_limit = RateLimitItemPerMinute(100)  # 100 requests per minute


class NoesisManager(NoesisServiceServicer):
    """
    Central orchestrator for Noesis operations, including configuration,
    task execution, adaptive learning, monitoring, and auditing.

    Attributes:
        task_executor (TaskExecutor): Handles task execution.
        adaptive_learning_manager (AdaptiveLearningManager): Manages adaptive learning.
        monitoring_service (MonitoringService): Monitors system performance.
        audit_manager (AuditManager): Retrieves and manages audit logs.
        active_configs (Dict[str, NoesisConfig]): Stores active configurations.
    """

    def __init__(self):
        """
        Initialize the NoesisManager and supporting components.
        """
        self.task_executor = TaskExecutor()
        self.adaptive_learning_manager = AdaptiveLearningManager()
        self.monitoring_service = MonitoringService()
        self.audit_manager = AuditManager()
        self.active_configs: Dict[str, NoesisConfig] = {}
        self.hyphen_local_states: Dict[str, Dict[str, Any]] = {}
        self.state_lock = Lock()  # Protect shared states with a thread-safe lock
        logger.info("NoesisManager initialized successfully.")

    def _sync_local_state(self, hyphen_id: str):
        """
        Synchronizes the local Noesis state with the global repository.

        Args:
            hyphen_id (str): Identifier for the Hyphen whose state is to be synced.
        """
        with self.state_lock:
            try:
                local_state = self.hyphen_local_states.get(hyphen_id, {})
                self.sync_manager.sync_state(hyphen_id, local_state)
                logger.info(f"Local state for Hyphen {hyphen_id} synced successfully.")
            except Exception as e:
                logger.error(f"Failed to sync state for Hyphen {hyphen_id}: {e}")

    # ================================
    # RPC Method: ConfigureNoesis
    # ================================
    def ConfigureNoesis(self, request: NoesisConfig, context) -> NoesisResponse:
        """
        Handles the ConfigureNoesis RPC to set up the Noesis system.

        Args:
            request (NoesisConfig): Configuration details.

        Returns:
            NoesisResponse: Confirmation of configuration status.
        """
        if not request.config_id:
            context.set_details("Configuration ID is required.")
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            return NoesisResponse(success=False, message="Configuration ID is required.")

        if not limiter.hit(rate_limit, request.config_id):
            context.set_details("Rate limit exceeded for configuration requests.")
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            return NoesisResponse(success=False, message="Rate limit exceeded.")

        try:
            logger.info(f"Configuring Noesis with ID: {request.config_id}")

            with self.state_lock:
                # Store configuration and initialize local state
                self.active_configs[request.config_id] = request
                self.hyphen_local_states[request.config_id] = {
                    "local_noesis_state": {},
                    "routing_table": {},
                    "feedback_loop": [],
                }

            self._sync_local_state(request.config_id)
            return NoesisResponse(
                success=True,
                message=f"Noesis configured successfully with ID: {request.config_id}",
                response_metadata=request.metadata,
            )
        except Exception as e:
            logger.error(f"Failed to configure Noesis: {e}")
            context.set_details(f"Configuration failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return NoesisResponse(success=False, message=f"Configuration failed: {e}")

    # ================================
    # RPC Method: ExecuteTask
    # ================================
    def ExecuteTask(self, request: NoesisTask, context) -> TaskResult:
        """
        Executes a task via the TaskExecutor.

        Args:
            request (NoesisTask): Task execution request.

        Returns:
            TaskResult: Outcome of the task execution.
        """
        try:
            logger.info(f"Executing task with ID: {request.task_id}")

            with self.state_lock:
                hyphen_state = self.hyphen_local_states.get(request.telemetry_id, {})

            result = self.task_executor.execute(request, hyphen_state)

            # Sync state post-execution
            self._sync_local_state(request.telemetry_id)

            return result
        except Exception as e:
            logger.error(f"Task execution failed for ID {request.task_id}: {e}")
            context.set_details(f"Task execution failed for ID {request.task_id}: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return TaskResult(
                task_id=request.task_id,
                outcome=2,  # TASK_FAILURE
                message=f"Task execution failed: {e}",
            )

    # ================================
    # RPC Method: StartAdaptiveLearning
    # ================================
    def StartAdaptiveLearning(self, request, context) -> LearningResult:
        """
        Starts an adaptive learning process.

        Args:
            request: Adaptive learning request.

        Returns:
            LearningResult: Outcome of the learning process.
        """
        try:
            logger.info(f"Starting adaptive learning for process ID: {request.process_id}")

            with self.state_lock:
                hyphen_state = self.hyphen_local_states.get(request.process_id, {})

            result = self.adaptive_learning_manager.start_learning(request, hyphen_state)

            # Sync state post-learning
            self._sync_local_state(request.process_id)

            return result
        except Exception as e:
            logger.error(f"Adaptive learning failed for process ID {request.process_id}: {e}")
            context.set_details(f"Adaptive learning failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return LearningResult(
                process_id=request.process_id,
                success=False,
                improvement_score=0.0,
                message=f"Adaptive learning failed: {e}",
            )

    # ================================
    # RPC Method: MonitorNoesis
    # ================================
    def MonitorNoesis(self, request: MonitoringRequest, context) -> NoesisMonitoring:
        """
        Monitors the performance and state of Noesis components.

        Args:
            request (MonitoringRequest): Monitoring request details.

        Returns:
            NoesisMonitoring: Monitoring data for the specified component.
        """
        try:
            logger.info(f"Monitoring Noesis component: {request.component_id}")
            return self.monitoring_service.monitor(request)
        except Exception as e:
            logger.error(f"Monitoring failed for component {request.component_id}: {e}")
            context.set_details(f"Monitoring failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return NoesisMonitoring()

    # ================================
    # RPC Method: GetAuditLogs
    # ================================
    def GetAuditLogs(self, request: AuditLogRequest, context) -> ConfigListResponse:
        """
        Retrieves audit logs for a specific component.

        Args:
            request (AuditLogRequest): Audit log request details.

        Returns:
            ConfigListResponse: List of retrieved audit logs.
        """
        try:
            logger.info(f"Retrieving audit logs for component: {request.component_id}")
            return self.audit_manager.get_logs(request)
        except Exception as e:
            logger.error(f"Failed to retrieve audit logs for component {request.component_id}: {e}")
            context.set_details(f"Failed to retrieve audit logs: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return ConfigListResponse()

    # ================================
    # RPC Method: GetTaskHistory
    # ================================
    def GetTaskHistory(self, request: TaskHistoryRequest, context) -> TaskHistoryResponse:
        """
        Retrieves task history for Noesis.

        Args:
            request (TaskHistoryRequest): Task history request details.

        Returns:
            TaskHistoryResponse: List of tasks within the specified range.
        """
        try:
            logger.info(f"Fetching task history for user: {request.initiated_by}")
            history = self.task_executor.get_task_history(request)
            return TaskHistoryResponse(tasks=history)
        except Exception as e:
            logger.error(f"Failed to fetch task history: {e}")
            context.set_details(f"Failed to fetch task history: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            return TaskHistoryResponse()
