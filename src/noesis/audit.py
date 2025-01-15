import logging
from typing import List, Dict, Optional
from datetime import datetime
from src.seigr_protocol.compiled.noesis_pb2 import (
    AuditLogRequest,
    AuditLogResponse,
    NoesisAuditLog,
)
from src.logger.secure_logger import secure_logger

# Initialize logger
logger = logging.getLogger(__name__)


class AuditManager:
    """
    Manages audit logs for Noesis operations, ensuring traceability,
    transparency, and secure storage of all actions.
    """

    def __init__(self):
        """
        Initializes the AuditManager with in-memory storage for logs
        and an optional persistence layer.
        """
        self.audit_logs: List[NoesisAuditLog] = []
        self.persistence_enabled = False  # Flag for persistence; configurable as needed.
        logger.info("AuditManager initialized with secure in-memory storage.")

    def log_event(
        self,
        log_id: str,
        action: str,
        performed_by: str,
        affected_component: str,
        corrective_action: str = "",
        audit_metadata: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Logs an audit event with detailed metadata.

        Args:
            log_id (str): Unique identifier for the log entry.
            action (str): Action performed (e.g., "CREATE", "MODIFY").
            performed_by (str): Entity performing the action.
            affected_component (str): Component affected by the action.
            corrective_action (str, optional): Corrective measures taken, if any.
            audit_metadata (dict, optional): Additional metadata for the log.
        """
        try:
            audit_metadata = audit_metadata or {}
            timestamp = datetime.utcnow().isoformat()

            audit_log = NoesisAuditLog(
                log_id=log_id,
                action=action,
                performed_by=performed_by,
                affected_component=affected_component,
                corrective_action=corrective_action,
                audit_metadata=audit_metadata,
                timestamp=timestamp,
            )
            self.audit_logs.append(audit_log)

            if self.persistence_enabled:
                self._persist_log(audit_log)

            logger.info(f"Audit log recorded: {log_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Audit",
                message=f"Audit log recorded for action: {action}",
                sensitive=False,
            )
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Audit",
                message=f"Failed to log audit event: {e}",
                sensitive=True,
            )
            raise ValueError("Failed to log audit event.") from e

    def get_logs(self, request: AuditLogRequest) -> AuditLogResponse:
        """
        Retrieves and filters audit logs based on the specified request.

        Args:
            request (AuditLogRequest): Request specifying filters for logs.

        Returns:
            AuditLogResponse: Response containing the filtered audit logs.
        """
        try:
            logger.info(f"Fetching audit logs for component: {request.component_id}")
            filtered_logs = [log for log in self.audit_logs if self._filter_log(log, request)]

            logger.info(
                f"Retrieved {len(filtered_logs)} audit logs for component: {request.component_id}"
            )
            secure_logger.log_audit_event(
                severity=1,
                category="Audit",
                message=f"Retrieved {len(filtered_logs)} audit logs.",
                sensitive=False,
            )

            return AuditLogResponse(
                logs=filtered_logs,
                status="SUCCESS",
                message=f"{len(filtered_logs)} logs retrieved.",
            )
        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Audit",
                message=f"Failed to retrieve audit logs: {e}",
                sensitive=True,
            )
            return AuditLogResponse(
                logs=[],
                status="FAILURE",
                message=f"Failed to retrieve logs: {e}",
            )

    def _filter_log(self, log: NoesisAuditLog, request: AuditLogRequest) -> bool:
        """
        Filters an audit log entry based on the provided request criteria.

        Args:
            log (NoesisAuditLog): The audit log entry to filter.
            request (AuditLogRequest): The filter criteria.

        Returns:
            bool: True if the log matches the filter, False otherwise.
        """
        # Filter by component ID
        if request.component_id and log.affected_component != request.component_id:
            return False

        # Filter by time range
        if request.time_range_start or request.time_range_end:
            log_time = datetime.fromisoformat(log.timestamp)
            if request.time_range_start and log_time < request.time_range_start.ToDatetime():
                return False
            if request.time_range_end and log_time > request.time_range_end.ToDatetime():
                return False

        # Filter by metadata
        for key, value in request.filters.items():
            if log.audit_metadata.get(key) != value:
                return False

        return True

    def _persist_log(self, audit_log: NoesisAuditLog) -> None:
        """
        Persists an audit log to a database or file-based storage.

        Args:
            audit_log (NoesisAuditLog): The log to persist.
        """
        try:
            # Placeholder: Implement actual persistence logic here.
            logger.debug(f"Persisting audit log: {audit_log.log_id}")
        except Exception as e:
            logger.error(f"Failed to persist audit log {audit_log.log_id}: {e}")
            raise ValueError(f"Persistence failed for audit log {audit_log.log_id}")

    def enable_persistence(self):
        """
        Enables the persistence layer for audit logs.
        """
        self.persistence_enabled = True
        logger.info("Persistence layer enabled for audit logs.")

    def disable_persistence(self):
        """
        Disables the persistence layer for audit logs.
        """
        self.persistence_enabled = False
        logger.info("Persistence layer disabled for audit logs.")
