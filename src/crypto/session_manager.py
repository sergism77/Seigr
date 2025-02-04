"""
📌 **Secure Session Manager**
Manages **secure sessions using encryption, structured metadata, session validation, and expiration handling**  
in compliance with **Seigr security protocols**.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.key_derivation import derive_key, generate_salt
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity

logger = logging.getLogger(__name__)

# ===============================
# 🔒 **Session Manager Class**
# ===============================


class SessionManager:
    """
    **Handles secure session lifecycle management.**
    Supports **session creation, validation, expiration cleanup, and invalidation**
    with cryptographic protections.
    """

    def __init__(
        self,
        session_store: str = "sessions",
        session_timeout: int = 3600,
        use_senary: bool = False,
    ):
        """
        **Initialize the SessionManager.**

        Args:
            session_store (str): **Directory to store session files.**
            session_timeout (int): **Session timeout in seconds.**
            use_senary (bool): **If True, encode session tokens in Senary format.**
        """
        self.session_store = session_store
        self.session_timeout = timedelta(seconds=session_timeout)
        self.use_senary = use_senary

        os.makedirs(self.session_store, exist_ok=True)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Session Management",
            message=f"{SEIGR_CELL_ID_PREFIX} SessionManager initialized. "
            f"Store: {session_store}, Timeout: {session_timeout}s, Senary: {use_senary}",
        )

    # ===============================
    # 🛠 **Session Creation**
    # ===============================

    def create_session(self, user_id: str, metadata: Optional[Dict] = None) -> str:
        """
        **Creates a new session with a unique token.**

        Args:
            user_id (str): **Identifier for the user.**
            metadata (Optional[Dict]): **Additional session metadata.**

        Returns:
            str: **Session token.**
        """
        try:
            session_id = f"{SEIGR_CELL_ID_PREFIX}_session_{uuid.uuid4()}"
            session_token = derive_key(
                password=session_id,
                salt=generate_salt(),
                use_senary=self.use_senary,
            )

            session_data = {
                "session_id": session_id,
                "user_id": user_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + self.session_timeout).isoformat(),
                "metadata": metadata or {},
            }

            session_file = os.path.join(self.session_store, f"{session_id}.json")
            with open(session_file, "w") as f:
                json.dump(session_data, f)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Session Management",
                message=f"{SEIGR_CELL_ID_PREFIX} Created new session: {session_id} for user: {user_id}",
            )
            return session_token
        except Exception as e:
            self._log_and_raise_error("session_creation_fail", "Failed to create session", e)

    # ===============================
    # ✅ **Session Validation**
    # ===============================

    def validate_session(self, session_token: str) -> bool:
        """
        **Validates a session based on the token.**

        Args:
            session_token (str): **Token associated with the session.**

        Returns:
            bool: **True if session is valid, False otherwise.**
        """
        try:
            session_files = os.listdir(self.session_store)
            for session_file in session_files:
                with open(os.path.join(self.session_store, session_file), "r") as f:
                    session_data = json.load(f)
                    derived_token = derive_key(
                        password=session_data["session_id"],
                        salt=generate_salt(),
                        use_senary=self.use_senary,
                    )
                    if derived_token == session_token:
                        expires_at = datetime.fromisoformat(session_data["expires_at"])
                        if datetime.now(timezone.utc) < expires_at:
                            secure_logger.log_audit_event(
                                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                                category="Session Management",
                                message=f"{SEIGR_CELL_ID_PREFIX} Session validated: {session_data['session_id']}",
                            )
                            return True
                        else:
                            secure_logger.log_audit_event(
                                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                                category="Session Management",
                                message=f"{SEIGR_CELL_ID_PREFIX} Session expired: {session_data['session_id']}",
                            )
                            return False
            return False
        except Exception as e:
            self._log_and_raise_error("session_validation_fail", "Failed to validate session", e)

    # ===============================
    # ❌ **Session Invalidation**
    # ===============================

    def invalidate_session(self, session_token: str) -> bool:
        """
        **Invalidates a session by deleting its corresponding file.**

        Args:
            session_token (str): **Token associated with the session.**

        Returns:
            bool: **True if session was invalidated, False otherwise.**
        """
        try:
            session_files = os.listdir(self.session_store)
            for session_file in session_files:
                with open(os.path.join(self.session_store, session_file), "r") as f:
                    session_data = json.load(f)
                    derived_token = derive_key(
                        password=session_data["session_id"],
                        salt=generate_salt(),
                        use_senary=self.use_senary,
                    )
                    if derived_token == session_token:
                        os.remove(os.path.join(self.session_store, session_file))
                        secure_logger.log_audit_event(
                            severity=AlertSeverity.ALERT_SEVERITY_INFO,
                            category="Session Management",
                            message=f"{SEIGR_CELL_ID_PREFIX} Session invalidated: {session_data['session_id']}",
                        )
                        return True
            return False
        except Exception as e:
            self._log_and_raise_error(
                "session_invalidation_fail", "Failed to invalidate session", e
            )

    # ===============================
    # 🧹 **Expired Session Cleanup**
    # ===============================

    def cleanup_expired_sessions(self) -> int:
        """
        **Removes expired sessions from the store.**

        Returns:
            int: **Number of cleaned-up sessions.**
        """
        try:
            cleaned_count = 0
            current_time = datetime.now(timezone.utc)
            for session_file in os.listdir(self.session_store):
                with open(os.path.join(self.session_store, session_file), "r") as f:
                    session_data = json.load(f)
                    expires_at = datetime.fromisoformat(session_data["expires_at"])
                    if current_time > expires_at:
                        os.remove(os.path.join(self.session_store, session_file))
                        cleaned_count += 1
                        secure_logger.log_audit_event(
                            severity=AlertSeverity.ALERT_SEVERITY_INFO,
                            category="Session Management",
                            message=f"{SEIGR_CELL_ID_PREFIX} Expired session cleaned: {session_data['session_id']}",
                        )
            return cleaned_count
        except Exception as e:
            self._log_and_raise_error(
                "session_cleanup_fail", "Failed to clean up expired sessions", e
            )

    # ===============================
    # ⚠️ **Structured Error Logging**
    # ===============================

    def _log_and_raise_error(self, error_id: str, message: str, exception: Exception):
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Session Management",
            message=f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}",
        )
        logger.error(f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}")
        raise exception
