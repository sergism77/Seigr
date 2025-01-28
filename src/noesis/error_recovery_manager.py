import logging
from typing import Callable, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from threading import Lock

# Initialize logger
logger = logging.getLogger(__name__)


class ErrorRecoveryManager:
    """
    Manages error handling, task retries, and graceful recovery
    for failed tasks in the Noesis system.

    Attributes:
        retry_policies (Dict[str, Dict[str, Any]]): Customizable retry policies for specific tasks.
        recovery_log (Dict[str, Dict[str, Any]]): Log of recovery attempts and outcomes.
        lock (Lock): Ensures thread-safe operations on shared resources.
    """

    def __init__(self):
        """
        Initializes the ErrorRecoveryManager with default retry policies and recovery log.
        """
        self.retry_policies: Dict[str, Dict[str, Any]] = {}
        self.recovery_log: Dict[str, Dict[str, Any]] = {}
        self.lock = Lock()  # Thread-safe access to recovery log and policies
        logger.info("ErrorRecoveryManager initialized successfully.")

    def register_retry_policy(
        self, task_type: str, max_retries: int, delay: int, backoff_factor: float = 2.0
    ):
        """
        Registers a retry policy for a specific task type.

        Args:
            task_type (str): The type of task (e.g., "pipeline_execution", "training").
            max_retries (int): Maximum number of retry attempts allowed.
            delay (int): Initial delay (in seconds) between retries.
            backoff_factor (float, optional): Factor by which delay increases after each retry.
        """
        with self.lock:
            self.retry_policies[task_type] = {
                "max_retries": max_retries,
                "delay": delay,
                "backoff_factor": backoff_factor,
            }
        logger.info(f"Retry policy registered for task type: {task_type}")

    def recover_task(
        self, task_id: str, task_type: str, task_function: Callable, *args, **kwargs
    ) -> Optional[Any]:
        """
        Attempts to recover a failed task using the configured retry policy.

        Args:
            task_id (str): Unique identifier for the task.
            task_type (str): The type of task being recovered.
            task_function (Callable): The function to execute for task recovery.
            *args: Positional arguments for the task function.
            **kwargs: Keyword arguments for the task function.

        Returns:
            Optional[Any]: The result of the recovered task, or None if recovery fails.
        """
        policy = self.retry_policies.get(task_type)
        if not policy:
            logger.error(f"No retry policy defined for task type: {task_type}")
            raise ValueError(f"No retry policy defined for task type: {task_type}")

        max_retries = policy["max_retries"]
        delay = policy["delay"]
        backoff_factor = policy["backoff_factor"]

        attempts = 0
        while attempts < max_retries:
            try:
                logger.info(f"Attempting recovery for task ID: {task_id} (Attempt {attempts + 1})")
                result = task_function(*args, **kwargs)
                self._log_recovery_attempt(task_id, task_type, success=True, attempt=attempts + 1)
                return result
            except Exception as e:
                attempts += 1
                self._log_recovery_attempt(
                    task_id, task_type, success=False, attempt=attempts, error=str(e)
                )
                logger.error(
                    f"Task recovery failed for task ID {task_id} (Attempt {attempts}): {e}"
                )
                if attempts < max_retries:
                    delay = delay * backoff_factor
                    logger.info(f"Retrying task ID {task_id} after {delay:.2f} seconds...")
                else:
                    logger.error(f"All recovery attempts failed for task ID: {task_id}")
                    break
        return None

    def _log_recovery_attempt(
        self, task_id: str, task_type: str, success: bool, attempt: int, error: Optional[str] = None
    ):
        """
        Logs the details of a recovery attempt.

        Args:
            task_id (str): Unique identifier for the task.
            task_type (str): The type of task.
            success (bool): Whether the recovery attempt was successful.
            attempt (int): The attempt number.
            error (str, optional): The error message if the attempt failed.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = {
            "timestamp": timestamp,
            "task_type": task_type,
            "attempt": attempt,
            "success": success,
            "error": error,
        }

        with self.lock:
            if task_id not in self.recovery_log:
                self.recovery_log[task_id] = {"history": []}
            self.recovery_log[task_id]["history"].append(log_entry)

        if success:
            logger.info(f"Recovery attempt successful for task ID: {task_id}")
        else:
            logger.warning(f"Recovery attempt failed for task ID: {task_id}")

    def get_recovery_log(self, task_id: str) -> Dict[str, Any]:
        """
        Retrieves the recovery log for a specific task.

        Args:
            task_id (str): Unique identifier for the task.

        Returns:
            Dict[str, Any]: The recovery log for the specified task.
        """
        with self.lock:
            log = self.recovery_log.get(task_id, {})
        logger.debug(f"Retrieved recovery log for task ID: {task_id}")
        return log

    def clear_recovery_log(self, task_id: str):
        """
        Clears the recovery log for a specific task.

        Args:
            task_id (str): Unique identifier for the task.
        """
        with self.lock:
            if task_id in self.recovery_log:
                del self.recovery_log[task_id]
        logger.info(f"Cleared recovery log for task ID: {task_id}")

    def clear_all_logs(self):
        """
        Clears all recovery logs from memory.
        """
        with self.lock:
            self.recovery_log.clear()
        logger.info("All recovery logs cleared.")
