# src/crypto/session_manager.py

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.key_derivation import derive_key, generate_salt
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)

logger = logging.getLogger(__name__)


### 📚 Session Manager ###


class SessionManager:
    """
    Manages secure sessions using encryption and structured metadata.
    Supports session creation, validation, and cleanup.
    """

    def __init__(
        self,
        session_store: str = "sessions",
        session_timeout: int = 3600,
        use_senary: bool = False,
    ):
        """
        Initialize the SessionManager.

        Args:
            session_store (str): Directory to store session files.
            session_timeout (int): Session timeout in seconds.
            use_senary (bool): If True, encode session tokens in Senary format.
        """
        self.session_store = session_store
        self.session_timeout = timedelta(seconds=session_timeout)
        self.use_senary = use_senary

        os.makedirs(self.session_store, exist_ok=True)
        logger.debug(
            f"{SEIGR_CELL_ID_PREFIX} SessionManager initialized. "
            f"Store: {session_store}, Timeout: {session_timeout}s, Senary: {use_senary}"
        )

    def create_session(self, user_id: str, metadata: Optional[Dict] = None) -> str:
        """
        Creates a new session with a unique token.

        Args:
            user_id (str): Identifier for the user.
            metadata (Optional[Dict]): Additional session metadata.

        Returns:
            str: Session token.
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

            logger.info(
                f"{SEIGR_CELL_ID_PREFIX} Created new session: {session_id} for user: {user_id}"
            )
            return session_token
        except Exception as e:
            self._log_and_raise_error("session_creation_fail", "Failed to create session", e)

    def validate_session(self, session_token: str) -> bool:
        """
        Validates a session based on the token.

        Args:
            session_token (str): Token associated with the session.

        Returns:
            bool: True if session is valid, False otherwise.
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
                            logger.info(
                                f"{SEIGR_CELL_ID_PREFIX} Session validated: "
                                f"{session_data['session_id']}"
                            )
                            return True
                        else:
                            logger.warning(
                                f"{SEIGR_CELL_ID_PREFIX} Session expired: "
                                f"{session_data['session_id']}"
                            )
                            return False
            return False
        except Exception as e:
            self._log_and_raise_error("session_validation_fail", "Failed to validate session", e)

    def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidates a session by deleting its corresponding file.

        Args:
            session_token (str): Token associated with the session.

        Returns:
            bool: True if session was invalidated, False otherwise.
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
                        logger.info(
                            f"{SEIGR_CELL_ID_PREFIX} Session invalidated: "
                            f"{session_data['session_id']}"
                        )
                        return True
            return False
        except Exception as e:
            self._log_and_raise_error(
                "session_invalidation_fail", "Failed to invalidate session", e
            )

    def cleanup_expired_sessions(self) -> int:
        """
        Removes expired sessions from the store.

        Returns:
            int: Number of cleaned-up sessions.
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
                        logger.info(
                            f"{SEIGR_CELL_ID_PREFIX} Expired session cleaned: "
                            f"{session_data['session_id']}"
                        )
            return cleaned_count
        except Exception as e:
            self._log_and_raise_error(
                "session_cleanup_fail", "Failed to clean up expired sessions", e
            )

    def _log_and_raise_error(self, error_id: str, message: str, exception: Exception):
        """
        Logs an error and raises it.

        Args:
            error_id (str): Unique identifier for the error.
            message (str): Error message.
            exception (Exception): The raised exception.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Session Manager",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{message}: {exception}")
        raise exception


### 🛠️ Top-Level API ###

_session_manager_instance = None


def _initialize_session_manager():
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = SessionManager()


def create_session(user_id: str, metadata: Optional[Dict] = None) -> str:
    _initialize_session_manager()
    return _session_manager_instance.create_session(user_id, metadata)


def validate_session(session_token: str) -> bool:
    _initialize_session_manager()
    return _session_manager_instance.validate_session(session_token)


def invalidate_session(session_token: str) -> bool:
    _initialize_session_manager()
    return _session_manager_instance.invalidate_session(session_token)


def cleanup_expired_sessions() -> int:
    _initialize_session_manager()
    return _session_manager_instance.cleanup_expired_sessions()
