import os

from src.utils.timestamp_utils import get_current_protobuf_timestamp
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import OperationLog
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct Enum Import
from src.logger.secure_logger import secure_logger
from config import Config

bp = Blueprint("ping_routes", __name__)


@bp.route("/ping", methods=["POST"])
def ping():
    """Records a network ping for the Seigr ID, logging the timestamp."""

    # ✅ Get a Protobuf-compliant timestamp
    timestamp_proto = get_current_protobuf_timestamp()

    # ✅ Create an OperationLog entry for the ping
    ping_entry = OperationLog(
        operation_type="network_ping",
        performed_by="system",
        timestamp=timestamp_proto,  # ✅ Direct Protobuf Timestamp (no `.ToJsonString()`)
        status="success",
        details="Network ping recorded successfully",
    )

    # ✅ Ensure the log path exists
    os.makedirs(os.path.dirname(Config.PING_LOG_PATH), exist_ok=True)

    try:
        # ✅ Append the new ping to the log file in binary format
        with open(Config.PING_LOG_PATH, "ab") as f:
            f.write(ping_entry.SerializeToString() + b"\n")

        # ✅ Log the ping using SecureLogger
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Correct Severity Enum
            category="Ping",
            message="✅ Network ping recorded successfully.",
            sensitive=False,
        )

        # ✅ Return a Protobuf-compliant response
        response = make_response(ping_entry.SerializeToString())
        response.headers["Content-Type"] = "application/octet-stream"
        return response

    except IOError as e:
        # ✅ Log the error with SecureLogger
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,  # ✅ Proper error severity
            category="Ping",
            message=f"❌ Failed to log network ping: {e}",
            sensitive=True,
        )

        # ✅ Create an error response
        error_response = OperationLog(
            operation_type="network_ping",
            status="error",
            timestamp=timestamp_proto,
            details="Failed to log ping",
        )

        # ✅ Return a structured error response
        response = make_response(error_response.SerializeToString(), 500)
        response.headers["Content-Type"] = "application/octet-stream"
        return response
