from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class AccessControlManager:
    """
    Manages access control, tracking permissions and access history for users and nodes
    in the Seigr system.
    """

    DEFAULT_PERMISSIONS = {"read": True, "write": False, "rollback": False}
    ROLES = {
        "viewer": {"read": True, "write": False, "rollback": False},
        "editor": {"read": True, "write": True, "rollback": False},
        "admin": {"read": True, "write": True, "rollback": True},
        "AI/ML_process": {"read": True, "write": True, "analyze": True, "adapt": False, "rollback": False},
        "network_system": {"read": True, "write": True, "self_heal": True, "self_write": True, "rollback": True}
    }

    def __init__(self, creator_id: str):
        """
        Initializes an AccessControlManager with a creator and a default ACL entry for the creator.

        Args:
            creator_id (str): Unique identifier for the creator of the resource.
        """
        self.creator_id = creator_id
        self.acl: List[Dict[str, any]] = [{"user_id": creator_id, "role": "admin", "permissions": self.ROLES["admin"]}]
        self.access_context = {
            "access_count": 0,
            "last_accessed": "",
            "hyphen_access_history": []
        }
        logger.debug(f"AccessControlManager initialized for creator {creator_id} with default admin permissions")

    def record_access(self, hyphen_id: str) -> None:
        """
        Records access details including count, timestamp, and user (hyphen) ID.

        Args:
            hyphen_id (str): Identifier of the user or node accessing the resource.
        """
        self.access_context["access_count"] += 1
        self.access_context["last_accessed"] = datetime.now(timezone.utc).isoformat()
        self.access_context["hyphen_access_history"].append(hyphen_id)
        logger.debug(f"Access recorded for hyphen {hyphen_id}. Total accesses: {self.access_context['access_count']}")

    def add_acl_entry(self, user_id: str, role: str) -> None:
        """
        Adds a new ACL entry for a user with a specified role.

        Args:
            user_id (str): The user or node ID to add.
            role (str): Role to assign (e.g., 'viewer', 'editor', 'admin', 'AI/ML_process', 'network_system').

        Raises:
            ValueError: If the role is invalid.
        """
        if role not in self.ROLES:
            logger.error(f"Attempted to add invalid role '{role}' for user {user_id}")
            raise ValueError(f"Invalid role: {role}")
        self.acl.append({"user_id": user_id, "role": role, "permissions": self.ROLES[role]})
        logger.info(f"ACL entry added: user {user_id} with role {role}")

    def update_acl_permissions(self, user_id: str, permissions: Dict[str, bool]) -> None:
        """
        Updates permissions for a user in the ACL.

        Args:
            user_id (str): The user or node ID to update.
            permissions (dict): Dictionary of permissions to update.

        Raises:
            ValueError: If the user ID is not found in the ACL.
        """
        for entry in self.acl:
            if entry["user_id"] == user_id:
                entry["permissions"].update(permissions)
                logger.info(f"Permissions updated for user {user_id}: {permissions}")
                return
        logger.error(f"User {user_id} not found in ACL for permission update")
        raise ValueError(f"User {user_id} not found in ACL")

    def check_permission(self, user_id: str, permission: str) -> bool:
        """
        Checks if a user has a specific permission.

        Args:
            user_id (str): The user or node ID to check.
            permission (str): Permission to verify (e.g., "read", "write", "rollback", "analyze", "self_heal").

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        for entry in self.acl:
            if entry["user_id"] == user_id:
                has_permission = entry["permissions"].get(permission, False)
                logger.debug(f"Permission check for {user_id}: {permission} = {has_permission}")
                return has_permission
        logger.warning(f"Permission check failed: user {user_id} not found in ACL")
        return False

    def get_access_history(self) -> Dict[str, any]:
        """
        Retrieves the access history context, including access count, last accessed timestamp,
        and a list of historical access entries.

        Returns:
            dict: Dictionary with access count, last accessed timestamp, and history of accesses.
        """
        logger.debug(f"Access history retrieved: {self.access_context}")
        return self.access_context
