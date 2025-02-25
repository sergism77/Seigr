import logging
import time
from src.execution.capsule_runtime import CapsuleExecutor
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import SeedDotSeigr

logger = logging.getLogger("PingCapsule")

def ping_system():
    """Records a system ping timestamp in the Seigr Capsule Execution."""
    try:
        current_time = int(time.time())  # Unix timestamp for last ping
        seed = SeedDotSeigr(last_ping=current_time)  # Set last_ping field
        
        logger.info(f"Ping Capsule executed. Last ping timestamp: {current_time}")
        return seed.SerializeToString()  # Return updated SeedDotSeigr message
    
    except Exception as e:
        logger.error(f"Ping Capsule execution failed: {e}")
        return None  # Returning None in case of failure

# Register Task in Capsule Executor
CapsuleExecutor.register_task("ping_system", ping_system)
