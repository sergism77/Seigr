import pytest
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


def test_log_audit_event_info():
    try:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="TestCategory",
            message="Audit log test message",
            sensitive=False,
            use_senary=False,
        )
    except Exception as e:
        pytest.fail(f"Secure logging failed: {e}")


def test_log_audit_event_invalid_severity():
    with pytest.raises(ValueError):
        secure_logger.log_audit_event(
            severity=999,  # Invalid severity
            category="TestCategory",
            message="Invalid severity test",
            sensitive=False,
        )
