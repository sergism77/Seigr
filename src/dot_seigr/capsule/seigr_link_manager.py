from src.logger.secure_logger import secure_logger


class FileLinkManager:
    """
    Manages primary and secondary links for Seigr file segments, supporting link validation
    and ensuring that the primary and secondary links adhere to Seigr's structure.
    """

    def __init__(self):
        """
        Initializes the FileLinkManager with an empty set of primary and secondary links.
        """
        self.links = {"primary": None, "secondary": []}
        secure_logger.log_audit_event("info", "LinkManager", "FileLinkManager initialized.")

    def set_links(self, primary: str, secondary: list):
        """
        Sets the primary and secondary links for a Seigr file segment.

        Args:
            primary (str): Primary link hash.
            secondary (list): List of secondary link hashes.

        Raises:
            ValueError: If primary or secondary links are invalid.
        """
        if not isinstance(primary, str) or not primary:
            secure_logger.log_audit_event("error", "LinkManager", "Invalid primary link provided.")
            raise ValueError("Primary link must be a non-empty string.")

        if not isinstance(secondary, list) or not all(
            isinstance(link, str) and link for link in secondary
        ):
            secure_logger.log_audit_event(
                "error", "LinkManager", "Invalid secondary links provided."
            )
            raise ValueError("Secondary links must be a list of non-empty strings.")

        self.links["primary"] = primary
        self.links["secondary"] = secondary

        secure_logger.log_audit_event(
            "info",
            "LinkManager",
            f"Primary and secondary links set. Primary: {primary}, Secondary: {secondary}",
        )

    def get_links(self) -> dict:
        """
        Retrieves the current primary and secondary links for the file segment.

        Returns:
            dict: Dictionary containing 'primary' and 'secondary' links.
        """
        secure_logger.log_audit_event(
            "debug",
            "LinkManager",
            f"Retrieving links: Primary: {self.links['primary']}, Secondary: {self.links['secondary']}",
        )
        return self.links

    def validate_links(self) -> bool:
        """
        Validates that primary and secondary links are set and adhere to basic formatting requirements.

        Returns:
            bool: True if primary and secondary links are valid, False otherwise.
        """
        primary_valid = isinstance(self.links["primary"], str) and bool(self.links["primary"])
        secondary_valid = all(
            isinstance(link, str) and bool(link) for link in self.links["secondary"]
        )

        if primary_valid and secondary_valid:
            secure_logger.log_audit_event("info", "LinkManager", "Link validation successful.")
            return True
        else:
            secure_logger.log_audit_event("warning", "LinkManager", "Link validation failed.")
            return False

    def add_secondary_link(self, link: str):
        """
        Adds a secondary link to the list of secondary links.

        Args:
            link (str): A new secondary link to add.

        Raises:
            ValueError: If the link is not a valid non-empty string.
        """
        if not isinstance(link, str) or not link:
            secure_logger.log_audit_event(
                "error", "LinkManager", "Invalid secondary link provided."
            )
            raise ValueError("Secondary link must be a non-empty string.")

        self.links["secondary"].append(link)
        secure_logger.log_audit_event("info", "LinkManager", f"Added secondary link: {link}")

    def clear_links(self):
        """
        Clears all primary and secondary links.
        """
        self.links = {"primary": None, "secondary": []}
        secure_logger.log_audit_event(
            "info", "LinkManager", "Cleared all primary and secondary links."
        )
