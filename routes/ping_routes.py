# routes/ping_routes.py
import logging
import os
from datetime import datetime, timezone

from flask import Blueprint, Response

from config import Config
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import OperationLog

bp = Blueprint("ping_routes", __name__)
logger = logging.getLogger(__name__)


@bp.route("/ping", methods=["POST"])
def ping():
    """Records a network ping for the Seigr ID, logging the timestamp."""
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create an OperationLog entry for the ping
    ping_entry = OperationLog(
        operation_type="network_ping",
        performed_by="system",
        timestamp=timestamp,
        status="success",
        details="Network ping recorded successfully",
    )

    # Ensure the log path exists
    os.makedirs(os.path.dirname(Config.PING_LOG_PATH), exist_ok=True)

    try:
        # Append the new ping to the log file in binary format
        with open(Config.PING_LOG_PATH, "ab") as f:
            f.write(ping_entry.SerializeToString() + b"\n")

        # Return a binary response with the ping status
        return Response(
            ping_entry.SerializeToString(), content_type="application/octet-stream"
        )

    except Exception as e:
        logger.error(f"Failed to log ping: {e}")
        error_response = OperationLog(
            operation_type="network_ping",
            status="error",
            timestamp=timestamp,
            details="Failed to log ping",
        )
        return Response(
            error_response.SerializeToString(),
            content_type="application/octet-stream",
            status=500,
        )
