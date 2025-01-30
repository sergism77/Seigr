# routes/ping_routes.py
import logging
import os
from datetime import datetime, timezone

from flask import Blueprint, Response, make_response
from google.protobuf.timestamp_pb2 import Timestamp

from config import Config
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import OperationLog
from src.logger.secure_logger import secure_logger

bp = Blueprint("ping_routes", __name__)
logger = logging.getLogger(__name__)


@bp.route("/ping", methods=["POST"])
def ping():
    """Records a network ping for the Seigr ID, logging the timestamp."""

    # ✅ Create a Protobuf-compliant timestamp
    timestamp_proto = Timestamp()
    timestamp_proto.FromDatetime(datetime.now(timezone.utc))

    # ✅ Create an OperationLog entry for the ping
    ping_entry = OperationLog(
        operation_type="network_ping",
        performed_by="system",
        timestamp=timestamp_proto.ToJsonString(),  # ✅ Proper Protobuf timestamp
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
            severity=1,
            category="Ping",
            message="Network ping recorded successfully.",
            sensitive=False,
        )

        # ✅ Return a Protobuf-compliant response
        response = make_response(ping_entry.SerializeToString())
        response.headers["Content-Type"] = "application/octet-stream"
        return response

    except IOError as e:
        logger.error(f"Failed to log ping: {e}")

        # ✅ Log the error with SecureLogger
        secure_logger.log_audit_event(
            severity=4,
            category="Ping",
            message=f"Failed to log network ping: {e}",
            sensitive=True,
        )

        # ✅ Create an error response
        error_response = OperationLog(
            operation_type="network_ping",
            status="error",
            timestamp=timestamp_proto.ToJsonString(),
            details="Failed to log ping",
        )

        # ✅ Return a structured error response
        response = make_response(error_response.SerializeToString(), 500)
        response.headers["Content-Type"] = "application/octet-stream"
        return response
