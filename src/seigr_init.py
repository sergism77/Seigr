import logging
import signal
import time
import importlib.util
import os

from src.execution.capsule_runtime import CapsuleExecutor

logger = logging.getLogger("SeigrOS")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")

class SeigrOS:
    """Core execution runtime for Seigr OS. Manages Capsule Execution and Task Dispatching."""

    def __init__(self):
        """Initialize Seigr OS and register execution tasks dynamically."""
        logger.info("Initializing Seigr OS Execution Environment...")

        # Dynamically Load All Capsules
        self.load_capsules()

        logger.info("Seigr OS is ready. Listening for Capsule Execution Tasks.")

    def load_capsules(self):
        """Dynamically imports and registers all capsules from `/capsules/`."""
        capsules_dir = os.path.join(os.path.dirname(__file__), "capsules")
        
        for filename in os.listdir(capsules_dir):
            if filename.endswith("_capsule.py"):
                module_name = filename[:-3]  # Remove `.py`
                module_path = os.path.join(capsules_dir, filename)

                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                logger.info(f"Loaded capsule: {module_name}")

    def run(self):
        """Main event loop for capsule execution. Runs as a daemonized process."""
        try:
            while True:
                time.sleep(1)  # Keeps Seigr OS running in the background
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        """Graceful shutdown of Seigr OS."""
        logger.info("Seigr OS is shutting down...")
        exit(0)

# Signal Handling for Safe Exit
def handle_signal(signal_number, frame):
    seigr_os.shutdown()

if __name__ == "__main__":
    # Start Seigr OS
    seigr_os = SeigrOS()

    # Handle system signals (SIGINT, SIGTERM)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Start execution loop
    seigr_os.run()
