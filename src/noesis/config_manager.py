import logging
from typing import Dict, Any, Optional, List
from threading import Lock
from datetime import datetime, timezone
from src.seigr_protocol.compiled.noesis_pb2 import SeigrConfig
from google.protobuf.json_format import MessageToDict, ParseDict
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Centralized configuration manager for the Noesis system, enabling the management
    of configurations in native Seigr formats while supporting optional `.yaml` or `.json`
    for external use cases.

    Attributes:
        active_configs (dict): Stores active configurations for different components.
        lock (Lock): Ensures thread-safe access to configurations.
    """

    def __init__(self):
        """
        Initializes the ConfigManager with an empty set of active configurations.
        """
        self.active_configs: Dict[str, SeigrConfig] = {}
        self.lock = Lock()  # Thread-safe configuration updates
        logger.info("ConfigManager initialized successfully.")

    def load_from_seigr(self, component: str, config_data: Dict[str, Any]) -> None:
        """
        Loads configuration from a native `.seigr` file or directly from a dictionary
        adhering to the SeigrConfig schema.

        Args:
            component (str): Name of the component to load the configuration for.
            config_data (Dict[str, Any]): Configuration data as a dictionary.

        Raises:
            ValueError: If the configuration data is invalid.
        """
        try:
            with self.lock:
                logger.info(
                    f"Loading configuration for component '{component}' from native format."
                )
                config = ParseDict(config_data, SeigrConfig())
                self.active_configs[component] = config
                logger.info(f"Configuration for component '{component}' loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load configuration for component '{component}': {e}")
            raise ValueError(f"Invalid configuration data for component '{component}'.") from e

    def get_config(self, component: str) -> SeigrConfig:
        """
        Retrieves the active configuration for a specific component.

        Args:
            component (str): Name of the component.

        Returns:
            SeigrConfig: The active configuration for the component.

        Raises:
            KeyError: If the configuration is not found.
        """
        with self.lock:
            if component not in self.active_configs:
                raise KeyError(f"Configuration for component '{component}' not found.")
            return self.active_configs[component]

    def update_config(self, component: str, updates: Dict[str, Any]) -> None:
        """
        Updates the active configuration for a specific component.

        Args:
            component (str): Name of the component.
            updates (Dict[str, Any]): Updates to apply as a dictionary.

        Raises:
            ValueError: If the updates are invalid.
        """
        with self.lock:
            if component not in self.active_configs:
                raise KeyError(f"Configuration for component '{component}' not found.")

            try:
                logger.info(f"Updating configuration for component '{component}'.")
                updated_config = ParseDict(updates, self.active_configs[component])
                self.active_configs[component] = updated_config
                logger.info(f"Configuration for component '{component}' updated successfully.")
            except Exception as e:
                logger.error(f"Failed to update configuration for component '{component}': {e}")
                raise ValueError(f"Invalid updates for component '{component}'.") from e

    def export_to_dict(self, component: str) -> Dict[str, Any]:
        """
        Exports the active configuration for a component as a dictionary.

        Args:
            component (str): Name of the component.

        Returns:
            Dict[str, Any]: Configuration data as a dictionary.

        Raises:
            KeyError: If the configuration is not found.
        """
        with self.lock:
            if component not in self.active_configs:
                raise KeyError(f"Configuration for component '{component}' not found.")

            logger.info(f"Exporting configuration for component '{component}' as dictionary.")

            # ✅ Fix: Use the correct argument to preserve snake_case field names
            return MessageToDict(self.active_configs[component], preserving_proto_field_name=True)

    def reset_to_default(self, component: str, default_config: Dict[str, Any]) -> None:
        """
        Resets the configuration for a component to its default values.

        Args:
            component (str): Name of the component.
            default_config (Dict[str, Any]): Default configuration data as a dictionary.

        Raises:
            ValueError: If the default configuration is invalid.
        """
        try:
            with self.lock:
                logger.info(f"Resetting configuration for component '{component}' to default.")
                self.active_configs[component] = ParseDict(default_config, SeigrConfig())
                logger.info(f"Configuration for component '{component}' reset successfully.")
        except Exception as e:
            logger.error(f"Failed to reset configuration for component '{component}': {e}")
            raise ValueError(f"Invalid default configuration for component '{component}'.") from e

    def list_components(self) -> List[str]:
        """
        Lists all components with active configurations.

        Returns:
            List[str]: List of component names.
        """
        with self.lock:
            components = list(self.active_configs.keys())
        logger.info(f"Active components: {components}")
        return components

    def export_to_file(self, component: str, file_path: str, format: str = "seigr") -> None:
        """
        Exports the configuration for a component to a file in the specified format.

        Args:
            component (str): Name of the component.
            file_path (str): Path to the file.
            format (str): Format to export (`seigr`, `yaml`, `json`).

        Raises:
            ValueError: If the format is unsupported.
            KeyError: If the configuration is not found.
        """
        with self.lock:
            if component not in self.active_configs:
                raise KeyError(f"Configuration for component '{component}' not found.")

            try:
                config_data = self.export_to_dict(component)

                if format == "seigr":
                    logger.info(
                        f"Exporting configuration for component '{component}' to {file_path} (Seigr format)."
                    )
                    with open(file_path, "w") as file:
                        file.write(str(config_data))  # Placeholder for Seigr-specific serialization
                elif format == "yaml":
                    import yaml

                    logger.info(
                        f"Exporting configuration for component '{component}' to {file_path} (YAML format)."
                    )
                    with open(file_path, "w") as file:
                        yaml.dump(config_data, file)
                elif format == "json":
                    import json

                    logger.info(
                        f"Exporting configuration for component '{component}' to {file_path} (JSON format)."
                    )
                    with open(file_path, "w") as file:
                        json.dump(config_data, file, indent=4)
                else:
                    raise ValueError(
                        f"Unsupported export format: {format}. Use 'seigr', 'yaml', or 'json'."
                    )

                logger.info(f"Configuration for component '{component}' exported successfully.")
            except Exception as e:
                logger.error(f"Failed to export configuration for component '{component}': {e}")
                raise
