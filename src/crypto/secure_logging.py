import logging
import os
import json
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from src.crypto.key_derivation import generate_salt, derive_key
from src.crypto.helpers import encode_to_senary, decode_from_senary
from src.seigr_protocol.compiled.audit_logging_pb2 import AuditLogEntry, LogSeverity, LogCategory
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

# Initialize the logger
logger = logging.getLogger("secure_logger")
logging.basicConfig(
    filename='secure_audit.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class SecureLogger:
    def __init__(self, encryption_key: bytes = None):
        """
        Initializes SecureLogger with an encryption key for sensitive log entries.
        
        Args:
            encryption_key (bytes): Encryption key for secure logging. Generates a new key if not provided.
        """
        self.encryption_key = encryption_key or self._generate_encryption_key()

    def _generate_encryption_key(self) -> bytes:
        """Generates a secure encryption key."""
        key = Fernet.generate_key()
        logger.debug("Generated new encryption key for secure logging.")
        return key

    def encrypt_message(self, message: str, use_senary: bool = False) -> bytes:
        """Encrypts a message, optionally encoding it in senary format."""
        fernet = Fernet(self.encryption_key)
        encrypted_message = fernet.encrypt(message.encode())
        
        if use_senary:
            encrypted_message = encode_to_senary(encrypted_message)
            logger.debug("Message encrypted and senary-encoded for secure logging.")
        else:
            logger.debug("Message encrypted for secure logging.")
        
        return encrypted_message

    def decrypt_message(self, encrypted_message: bytes, is_senary: bool = False) -> str:
        """Decrypts an encrypted message, handling optional senary decoding."""
        try:
            if is_senary:
                encrypted_message = decode_from_senary(encrypted_message)
                
            fernet = Fernet(self.encryption_key)
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            logger.debug("Message decrypted from secure logging.")
            return decrypted_message
        except Exception as e:
            self._log_error("decryption_fail", "Decryption failed for sensitive log message", e)
            raise ValueError("Decryption error in secure logging")

    def log_audit_event(self, severity: LogSeverity, category: LogCategory, message: str, sensitive: bool = False, use_senary: bool = False) -> AuditLogEntry:
        """
        Logs an audit event with optional encryption and senary encoding for sensitive information.

        Args:
            severity (LogSeverity): Severity level of the log.
            category (LogCategory): Category of the log (e.g., ACCESS, ERROR).
            message (str): Log message.
            sensitive (bool): If True, the message is encrypted before logging.
            use_senary (bool): If True, the encrypted message is senary-encoded for consistency.

        Returns:
            AuditLogEntry: Structured audit log entry for secure records.
        """
        try:
            entry_id = f"log_{datetime.now(timezone.utc).isoformat()}"
            if sensitive:
                message = self.encrypt_message(message, use_senary=use_senary)
            
            audit_entry = AuditLogEntry(
                entry_id=entry_id,
                severity=severity,
                category=category,
                message=message,
                timestamp=datetime.now(timezone.utc).isoformat(),
                sensitive=sensitive,
                metadata={"senary_encoded": use_senary}
            )
            log_message = f"[{severity.name}] {category.name}: {audit_entry.message}"

            if sensitive:
                logger.info(f"{log_message} (Encrypted and Senary Encoded)" if use_senary else f"{log_message} (Encrypted)")
            else:
                logger.info(log_message)
            return audit_entry
        except Exception as e:
            self._log_error("audit_logging_fail", "Failed to log audit event", e)
            raise ValueError("Audit event logging failed.")

    def retrieve_logs(self, decrypt_sensitive: bool = False) -> list:
        """
        Retrieves and optionally decrypts all logs from the secure log file.

        Args:
            decrypt_sensitive (bool): Decrypts sensitive messages if True.

        Returns:
            list: List of decrypted and parsed logs.
        """
        try:
            with open("secure_audit.log", "r") as log_file:
                logs = []
                for line in log_file:
                    log_entry = json.loads(line)
                    if decrypt_sensitive and log_entry.get("sensitive"):
                        log_entry["message"] = self.decrypt_message(log_entry["message"], is_senary=log_entry.get("metadata", {}).get("senary_encoded", False))
                    logs.append(log_entry)
            logger.info("Logs retrieved from secure log file.")
            return logs
        except Exception as e:
            self._log_error("log_retrieval_fail", "Failed to retrieve logs from secure log file", e)
            raise ValueError("Log retrieval error.")

    def log_security_event(self, event_type: str, description: str, severity: LogSeverity, metadata: dict = None) -> AuditLogEntry:
        """
        Logs a security event, typically for access control and protocol integrity issues.

        Args:
            event_type (str): Type of the security event (e.g., ACCESS_DENIED, INTEGRITY_ALERT).
            description (str): Detailed description of the event.
            severity (LogSeverity): Severity level of the event.
            metadata (dict): Additional context information for the event.

        Returns:
            AuditLogEntry: Generated log entry for the security event.
        """
        try:
            entry_id = f"security_{datetime.now(timezone.utc).isoformat()}"
            log_entry = AuditLogEntry(
                entry_id=entry_id,
                severity=severity,
                category=LogCategory.SECURITY,
                message=f"{event_type}: {description}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata=metadata if metadata else {}
            )
            logger.warning(f"[{severity.name}] SECURITY: {log_entry.message} with metadata {log_entry.metadata}")
            return log_entry
        except Exception as e:
            self._log_error("security_logging_fail", "Failed to log security event", e)
            raise ValueError("Security event logging failed.")

    def rotate_encryption_key(self, reason: str = "Routine Rotation"):
        """
        Rotates the encryption key used for sensitive log entries, logging the event with additional metadata.
        
        Args:
            reason (str): Reason for rotation, e.g., "Routine Rotation" or "Compromise".
        """
        old_key = self.encryption_key
        self.encryption_key = self._generate_encryption_key()
        
        self.log_audit_event(
            severity=LogSeverity.INFO,
            category=LogCategory.SECURITY,
            message="Encryption key rotated for secure logging.",
            sensitive=False,
            use_senary=False
        )
        
        logger.info(f"Encryption key rotated successfully. Reason: {reason}")
        
        rotation_metadata = {
            "old_key_rotation_timestamp": datetime.now(timezone.utc).isoformat(),
            "rotation_reason": reason
        }
        
        return old_key, self.encryption_key, rotation_metadata  # Return metadata for external logging if needed

    def _log_error(self, error_id: str, message: str, exception: Exception):
        """Logs an error with detailed metadata."""
        error_log = ErrorLogEntry(
            error_id=f"secure_logger_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Secure Logger",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
        )
        logger.error(f"{message}: {exception}")
