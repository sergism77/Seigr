# routes/monitor_routes.py
from flask import Blueprint, Response
from config import Config
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import OperationLog
import os
import logging

bp = Blueprint("monitor_routes", __name__)
logger = logging.getLogger(__name__)


@bp.route("/get_activity_log", methods=["GET"])
def get_activity_log():
    """Returns the ping activity log for the Seigr ID."""
    if not os.path.exists(Config.PING_LOG_PATH):
        response = OperationLog(
            operation_type="ping_log", status="error", details="No activity log found"
        )
        return Response(
            response.SerializeToString(),
            content_type="application/octet-stream",
            status=404,
        )

    try:
        logs = []
        with open(Config.PING_LOG_PATH, "rb") as f:
            for line in f:
                log_entry = OperationLog()
                log_entry.ParseFromString(line.strip())
                logs.append(log_entry)

        # Serialize the entire log list into a single response
        response_data = b"".join(log.SerializeToString() for log in logs)
        return Response(response_data, content_type="application/octet-stream")

    except Exception as e:
        logger.error(f"Error reading activity log: {e}")
        response = OperationLog(
            operation_type="ping_log",
            status="error",
            details="Failed to retrieve activity log",
        )
        return Response(
            response.SerializeToString(),
            content_type="application/octet-stream",
            status=500,
        )
