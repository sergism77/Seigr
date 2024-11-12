class FileLinkManager:
    def __init__(self):
        """
        Manages primary and secondary links for Seigr file segments.
        """
        self.links = {"primary": None, "secondary": []}

    def set_links(self, primary, secondary):
        """
        Sets the primary and secondary links for a Seigr file segment.

        Args:
            primary (str): Primary link hash.
            secondary (list): List of secondary link hashes.
        """
        self.links["primary"] = primary
        self.links["secondary"] = secondary

    def get_links(self) -> dict:
        """
        Retrieves the current primary and secondary links for the file segment.

        Returns:
            dict: Dictionary containing 'primary' and 'secondary' links.
        """
        return self.links
