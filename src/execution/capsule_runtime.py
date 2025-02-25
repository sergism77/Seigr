import logging
import threading

logger = logging.getLogger(__name__)

class CapsuleExecutor:
    """Handles execution of Seigr Capsules (replacing HTTP-based API calls)."""
    
    _task_registry = {}

    @staticmethod
    def register_task(task_name, task_function):
        """Registers a function as a Capsule Execution Task."""
        CapsuleExecutor._task_registry[task_name] = task_function
        logger.info(f"Registered Capsule Execution Task: {task_name}")

    @staticmethod
    def execute_task(task_name, *args, **kwargs):
        """Executes a registered Capsule task asynchronously."""
        if task_name in CapsuleExecutor._task_registry:
            task_function = CapsuleExecutor._task_registry[task_name]
            thread = threading.Thread(target=task_function, args=args, kwargs=kwargs)
            thread.start()
            return f"Task {task_name} executed asynchronously"
        else:
            logger.error(f"Task {task_name} not found")
            return f"Task {task_name} not found"
