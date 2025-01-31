import logging
from datetime import datetime, timezone
from typing import Dict, List

from src.seigr_protocol.compiled.access_control_pb2 import (
    AccessPolicy,
    Permission,  # ✅ Corrected import, replacing removed `PermissionEntry`
    AccessAuditLog,  # ✅ Using `AccessAuditLog` for structured access logging
)
from src.logger.secure_logger import secure_logger


class AccessControlManager:
    """
    Manages access control, tracking permissions and access history for users and nodes
    in the Seigr system, ensuring strict compliance with `access_control.proto`.
    """

    ROLES = {
        "viewer": {"read": True, "write": False, "rollback": False},
        "editor": {"read": True, "write": True, "rollback": False},
        "admin": {"read": True, "write": True, "rollback": True},
        "AI/ML_process": {
            "read": True,
            "write": True,
            "analyze": True,
            "adapt": False,
            "rollback": False,
        },
        "network_system": {
            "read": True,
            "write": True,
            "self_heal": True,
            "self_write": True,
            "rollback": True,
        },
    }

    def __init__(self, creator_id: str):
        """
        Initializes an AccessControlManager with a creator and a default ACL entry.

        Args:
            creator_id (str): Unique identifier for the creator of the resource.
        """
        self.creator_id = creator_id
        self.acl: Dict[str, Dict] = {
            creator_id: {"role": "admin", "permissions": self.ROLES["admin"]}
        }
        self.access_context = {
            "access_count": 0,
            "last_accessed": None,
            "access_history": [],
        }
        secure_logger.log_audit_event(
            severity="info",
            category="Access Control",
            message=f"AccessControlManager initialized for {creator_id} with admin privileges.",
        )

    def record_access(self, user_id: str, action: int) -> None:
        """
        Records access details, ensuring structured logging.

        Args:
            user_id (str): Identifier of the user or node accessing the resource.
            action (int): Access action type (use `AccessType` enums from `access_control.proto`).
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        self.access_context["access_count"] += 1
        self.access_context["last_accessed"] = timestamp
        self.access_context["access_history"].append(user_id)

        # Structured event logging
        log_entry = AccessAuditLog(
            user_id=user_id,
            action=action,
            timestamp=timestamp,
            status="SUCCESS",
            details="Access granted.",
        )
        secure_logger.log_audit_event(
            severity="info",
            category="Access Log",
            message=f"Access recorded for {user_id}",
            log_data=log_entry,
        )

    def add_acl_entry(self, user_id: str, role: str) -> None:
        """
        Adds a new ACL entry for a user with a specified role.

        Args:
            user_id (str): The user or node ID to add.
            role (str): Role to assign (must match a valid role in `ROLES`).

        Raises:
            ValueError: If the role is invalid.
        """
        if role not in self.ROLES:
            secure_logger.log_audit_event(
                severity="error",
                category="Access Control",
                message=f"Invalid role assignment attempt: {role} for {user_id}",
            )
            raise ValueError(f"Invalid role: {role}")

        self.acl[user_id] = {"role": role, "permissions": self.ROLES[role]}
        secure_logger.log_audit_event(
            severity="info",
            category="Access Control",
            message=f"ACL entry added: {user_id} with role {role}",
        )

    def update_acl_permissions(self, user_id: str, permissions: Dict[str, bool]) -> None:
        """
        Updates permissions for a user in the ACL.

        Args:
            user_id (str): The user or node ID to update.
            permissions (dict): Dictionary of permissions to update.

        Raises:
            ValueError: If the user ID is not found in the ACL.
        """
        if user_id not in self.acl:
            secure_logger.log_audit_event(
                severity="error",
                category="Access Control",
                message=f"ACL update failed: User {user_id} not found",
            )
            raise ValueError(f"User {user_id} not found in ACL")

        self.acl[user_id]["permissions"].update(permissions)
        secure_logger.log_audit_event(
            severity="info",
            category="Access Control",
            message=f"Permissions updated for {user_id}: {permissions}",
        )

    def check_permission(self, user_id: str, permission: str) -> bool:
        """
        Checks if a user has a specific permission.

        Args:
            user_id (str): The user or node ID to check.
            permission (str): Permission to verify (e.g., "read", "write", "rollback").

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        if user_id in self.acl:
            has_permission = self.acl[user_id]["permissions"].get(permission, False)
            secure_logger.log_audit_event(
                severity="debug",
                category="Access Control",
                message=f"Permission check: {user_id} -> {permission} = {has_permission}",
            )
            return has_permission

        secure_logger.log_audit_event(
            severity="warning",
            category="Access Control",
            message=f"Permission check failed: {user_id} not found",
        )
        return False

    def remove_acl_entry(self, user_id: str) -> None:
        """
        Removes an ACL entry from the access control list.

        Args:
            user_id (str): The user or node ID to remove.

        Raises:
            ValueError: If the user is not found.
        """
        if user_id not in self.acl:
            secure_logger.log_audit_event(
                severity="error",
                category="Access Control",
                message=f"Failed ACL removal: User {user_id} not found",
            )
            raise ValueError(f"User {user_id} not found in ACL")

        del self.acl[user_id]
        secure_logger.log_audit_event(
            severity="info",
            category="Access Control",
            message=f"ACL entry removed: {user_id}",
        )

    def get_access_history(self) -> Dict[str, any]:
        """
        Retrieves the access history context, including access count, last accessed timestamp,
        and a list of historical access entries.

        Returns:
            dict: Dictionary with access count, last accessed timestamp, and history of accesses.
        """
        secure_logger.log_audit_event(
            severity="info",
            category="Access Log",
            message="Access history retrieved",
            log_data=self.access_context,
        )
        return self.access_context
