"""
📌 **Seigr Configuration Loader Module**
Centralized utility for **loading, validating, and managing configurations**.
Supports JSON & YAML with optional **Senary encoding**.
Ensures full **Seigr compliance, structured logging, and error handling**.
"""

import json
import os
import yaml
from typing import Any, Dict

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import encode_to_senary
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.logger.secure_logger import secure_logger


# ===============================
# 📊 **Configuration Loader Class**
# ===============================
class ConfigLoader:
    """
    **Handles structured loading, validation, and encoding of configuration files.**
    """

    def __init__(self, config_dir: str = "config", use_senary: bool = False):
        """
        **Initializes the ConfigLoader with structured logging and Seigr compliance.**

        Args:
            config_dir (str, optional): Directory containing configuration files (default: "config").
            use_senary (bool, optional): Whether to encode values in **Senary format** (default: False).
        """
        self.config_dir = config_dir
        self.use_senary = use_senary
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Config Loader",
            message=f"ConfigLoader initialized | Directory: {config_dir} | Senary Encoding: {use_senary}",
        )

    # ===============================
    # 📥 **Load Configuration**
    # ===============================
    def load_config(self, file_name: str) -> Dict[str, Any]:
        """
        **Loads a configuration file (JSON or YAML) in a structured, validated manner.**

        Args:
            file_name (str): Name of the configuration file.

        Returns:
            Dict[str, Any]: Loaded **validated configuration data**.
        """
        file_path = os.path.join(self.config_dir, file_name)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Config Loader",
            message=f"Loading configuration: {file_path}",
        )

        if not os.path.isfile(file_path):
            self._log_and_raise_error(
                "config_file_not_found",
                f"Configuration file missing: {file_path}",
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
                        f"Unsupported format: {file_name}",
                        ValueError,
                    )

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Config Loader",
                message=f"✅ Successfully loaded configuration: {file_name}",
            )
            return self._apply_senary_encoding(config) if self.use_senary else config
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            self._log_and_raise_error(
                "config_parse_error",
                f"Error parsing configuration file: {file_name}",
                e,
            )
        except Exception as e:
            self._log_and_raise_error(
                "config_load_fail",
                f"Configuration load failed: {file_name}",
                e,
            )

    # ===============================
    # ✅ **Validate Configuration**
    # ===============================
    def validate_config(self, config: Dict[str, Any], required_keys: list) -> bool:
        """
        **Validates a configuration dictionary against required keys.**

        Args:
            config (Dict[str, Any]): Configuration data.
            required_keys (list): Required keys.

        Returns:
            bool: **True if valid**, else raises an error.
        """
        missing_keys = [key for key in required_keys if key not in config]
        if missing_keys:
            self._log_and_raise_error(
                "config_validation_fail",
                f"❌ Missing required keys: {missing_keys}",
                ValueError,
            )

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Config Validation",
            message=f"✅ Configuration successfully validated.",
        )
        return True

    # ===============================
    # 🔄 **Reload Configuration**
    # ===============================
    def reload_config(self, file_name: str) -> Dict[str, Any]:
        """
        **Reloads a configuration file.**

        Args:
            file_name (str): Name of the configuration file.

        Returns:
            Dict[str, Any]: **Reloaded configuration data**.
        """
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Config Reload",
            message=f"🔄 Reloading configuration: {file_name}",
        )
        return self.load_config(file_name)

    # ===============================
    # 🔐 **Senary Encoding for Config Data**
    # ===============================
    def _apply_senary_encoding(self, data: Any) -> Any:
        """
        **Recursively applies Senary encoding to configuration values.**

        Args:
            data (Any): Data to encode.

        Returns:
            Any: **Senary-encoded configuration data**.
        """
        if isinstance(data, dict):
            return {k: self._apply_senary_encoding(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._apply_senary_encoding(v) for v in data]
        elif isinstance(data, (str, bytes)):
            return encode_to_senary(data.encode() if isinstance(data, str) else data)
        return data

    # ===============================
    # ⚠️ **Structured Error Handling**
    # ===============================
    def _log_and_raise_error(self, error_id: str, message: str, exception: Exception):
        """
        **Logs structured errors and raises the corresponding exceptions.**

        Args:
            error_id (str): Unique error identifier.
            message (str): Error message.
            exception (Exception): Exception object.

        Raises:
            Exception: **Raises the structured exception**.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Config Loader",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        secure_logger.log_audit_event(
            severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
            category="Configuration Error",
            message=f"🚨 {message}: {exception}",
            log_data=error_log,
        )
        raise exception


# ===============================
# 🔧 **Global Configuration Loader Instance**
# ===============================
_config_loader_instance = None


def _initialize_config_loader(config_dir: str = "config", use_senary: bool = False):
    """
    **Initializes the global ConfigLoader instance (if not already initialized).**
    """
    global _config_loader_instance
    if _config_loader_instance is None:
        _config_loader_instance = ConfigLoader(config_dir=config_dir, use_senary=use_senary)


# ===============================
# 🛠️ **Top-Level Helper Functions**
# ===============================
def load_config(file_name: str, use_senary: bool = False) -> Dict[str, Any]:
    """
    **Loads a configuration file using the global instance.**

    Args:
        file_name (str): Configuration file name.
        use_senary (bool, optional): Whether to use Senary encoding.

    Returns:
        Dict[str, Any]: **Loaded configuration data.**
    """
    _initialize_config_loader(use_senary=use_senary)
    return _config_loader_instance.load_config(file_name)


def validate_config(config: Dict[str, Any], required_keys: list) -> bool:
    """
    **Validates a configuration dictionary using the global instance.**

    Args:
        config (Dict[str, Any]): Configuration dictionary.
        required_keys (list): Required keys.

    Returns:
        bool: **True if valid**.
    """
    _initialize_config_loader()
    return _config_loader_instance.validate_config(config, required_keys)
