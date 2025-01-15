import logging

logger = logging.getLogger(__name__)


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
            raise ValueError("Primary link must be a non-empty string.")

        if not isinstance(secondary, list) or not all(isinstance(link, str) for link in secondary):
            raise ValueError("Secondary links must be a list of non-empty strings.")

        self.links["primary"] = primary
        self.links["secondary"] = secondary

        logger.info(f"Primary and secondary links set. Primary: {primary}, Secondary: {secondary}")

    def get_links(self) -> dict:
        """
        Retrieves the current primary and secondary links for the file segment.

        Returns:
            dict: Dictionary containing 'primary' and 'secondary' links.
        """
        logger.debug(
            f"Retrieving links: Primary: {self.links['primary']}, Secondary: {self.links['secondary']}"
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
            logger.info("Link validation successful for primary and secondary links.")
            return True
        else:
            logger.warning("Link validation failed. Check primary or secondary link formats.")
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
            raise ValueError("Secondary link must be a non-empty string.")

        self.links["secondary"].append(link)
        logger.info(f"Added secondary link: {link}")

    def clear_links(self):
        """
        Clears all primary and secondary links.
        """
        self.links = {"primary": None, "secondary": []}
        logger.info("Cleared all primary and secondary links.")
