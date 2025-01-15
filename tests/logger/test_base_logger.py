import pytest
from src.logger.base_logger import base_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


def test_log_message():
    try:
        base_logger.log_message(
            level="INFO", message="Logger test message", category="TestCategory", sensitive=False
        )
    except Exception as e:
        pytest.fail(f"Logging failed: {e}")


def test_invalid_log_level():
    with pytest.raises(ValueError):
        base_logger.log_message(
            level="INVALID", message="This should fail", category="TestCategory", sensitive=False
        )
