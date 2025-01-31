"""
📌 **Seigr Centralized Alert Utility**
Handles **structured alerting** using Seigr’s protocol.
"""

import uuid
from datetime import datetime, timezone
from google.protobuf.timestamp_pb2 import Timestamp
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.logger.secure_logger import secure_logger
from src.crypto.constants import SEIGR_CELL_ID_PREFIX


def trigger_alert(
    message: str, severity: AlertSeverity, alert_type: AlertType, source_component: str
) -> None:
    """
    **Triggers a structured alert following Seigr's protocol.**
    """
    protobuf_timestamp = Timestamp()
    protobuf_timestamp.FromDatetime(datetime.now(timezone.utc))

    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_alert_{protobuf_timestamp.seconds}",
        message=message,
        type=alert_type,
        severity=severity,
        timestamp=protobuf_timestamp,
        source_component=source_component,
    )

    category_mapping = {
        "asymmetric_utils": "Cryptography",
        "cbor_utils": "CBOR Operations",
    }
    log_category = category_mapping.get(source_component, source_component)

    secure_logger.log_audit_event(
        severity=severity,
        category=log_category,
        message=alert.message,
        timestamp=protobuf_timestamp,  # ✅ Always use Protobuf timestamp
        log_data={"alert_id": alert.alert_id},
    )
