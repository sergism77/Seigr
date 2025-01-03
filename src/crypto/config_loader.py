# src/crypto/config_loader.py

import os
import json
import yaml
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.crypto.helpers import encode_to_senary
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)

logger = logging.getLogger(__name__)


### 📚 Configuration Loader ###


class ConfigLoader:
    """
    A centralized utility to load and validate configuration files.
    Supports JSON and YAML formats with optional Senary encoding.
    """

    def __init__(self, config_dir: str = "config", use_senary: bool = False):
        """
        Initialize the configuration loader.

        Args:
            config_dir (str): Directory containing configuration files.
            use_senary (bool): Whether to encode configuration values in Senary.
        """
        self.config_dir = config_dir
        self.use_senary = use_senary
        logger.debug(
            f"{SEIGR_CELL_ID_PREFIX} ConfigLoader initialized for directory: {config_dir}, Senary: {use_senary}"
        )

    def load_config(self, file_name: str) -> Dict[str, Any]:
        """
        Load a configuration file (JSON or YAML).

        Args:
            file_name (str): Name of the configuration file.

        Returns:
            Dict[str, Any]: Loaded configuration data.
        """
        file_path = os.path.join(self.config_dir, file_name)
        logger.debug(
            f"{SEIGR_CELL_ID_PREFIX} Loading configuration from: {file_path}"
        )

        if not os.path.isfile(file_path):
            self._log_and_raise_error(
                "config_file_not_found",
                f"Configuration file not found: {file_path}",
                FileNotFoundError,
            )

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                if file_name.endswith(".json"):
                    config = json.load(f)
                elif file_name.endswith((".yaml", ".yml")):
                    config = yaml.safe_load(f)
                else:
                    self._log_and_raise_error(
                        "unsupported_config_format",
                        f"Unsupported configuration format: {file_name}",
                        ValueError,
                    )
            logger.info(f"{SEIGR_CELL_ID_PREFIX} Loaded configuration: {file_name}")
            return self._apply_senary_encoding(config) if self.use_senary else config
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            self._log_and_raise_error(
                "config_parse_error",
                f"Failed to parse configuration file: {file_name}",
                e,
            )
        except Exception as e:
            self._log_and_raise_error(
                "config_load_fail",
                f"Failed to load configuration file: {file_name}",
                e,
            )

    def validate_config(self, config: Dict[str, Any], required_keys: list) -> bool:
        """
        Validates a configuration dictionary against required keys.

        Args:
            config (Dict[str, Any]): Configuration data.
            required_keys (list): List of keys required in the configuration.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        missing_keys = [key for key in required_keys if key not in config]
        if missing_keys:
            self._log_and_raise_error(
                "config_validation_fail",
                f"Missing required configuration keys: {missing_keys}",
                ValueError,
            )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Configuration validated successfully.")
        return True

    def reload_config(self, file_name: str) -> Dict[str, Any]:
        """
        Reloads a configuration file.

        Args:
            file_name (str): Name of the configuration file.

        Returns:
            Dict[str, Any]: Reloaded configuration data.
        """
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Reloading configuration: {file_name}")
        return self.load_config(file_name)

    def _apply_senary_encoding(self, data: Any) -> Any:
        """
        Recursively applies Senary encoding to configuration values.

        Args:
            data (Any): Data to encode.

        Returns:
            Any: Senary-encoded configuration data.
        """
        if isinstance(data, dict):
            return {k: self._apply_senary_encoding(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._apply_senary_encoding(v) for v in data]
        elif isinstance(data, (str, bytes)):
            return encode_to_senary(data.encode() if isinstance(data, str) else data)
        return data

    def _log_and_raise_error(self, error_id: str, message: str, exception: Exception):
        """
        Logs and raises a structured error for configuration failures.

        Args:
            error_id (str): Unique identifier for the error.
            message (str): Descriptive error message.
            exception (Exception): Exception object.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Config Loader",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{message}: {exception}")
        raise exception


### 🛠️ Top-Level Functions ###


_config_loader_instance = None


def _initialize_config_loader(config_dir: str = "config", use_senary: bool = False):
    global _config_loader_instance
    if _config_loader_instance is None:
        _config_loader_instance = ConfigLoader(config_dir=config_dir, use_senary=use_senary)


def load_config(file_name: str, use_senary: bool = False) -> Dict[str, Any]:
    """
    Top-level function to load a configuration file.

    Args:
        file_name (str): Configuration file name.
        use_senary (bool): If True, applies senary encoding.

    Returns:
        Dict[str, Any]: Loaded configuration data.
    """
    _initialize_config_loader(use_senary=use_senary)
    return _config_loader_instance.load_config(file_name)


def validate_config(config: Dict[str, Any], required_keys: list) -> bool:
    """
    Top-level function to validate a configuration dictionary.

    Args:
        config (Dict[str, Any]): Configuration dictionary.
        required_keys (list): Required keys.

    Returns:
        bool: Validation status.
    """
    _initialize_config_loader()
    return _config_loader_instance.validate_config(config, required_keys)
