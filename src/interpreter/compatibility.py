import logging

logger = logging.getLogger(__name__)

SUPPORTED_VERSIONS = ["1.0", "1.1"]
DEPRECATED_VERSIONS = ["0.9"]

class VersionCompatibility:
    """
    Provides utilities to manage version compatibility for `.seigr` metadata and protocol formats.
    """

    def __init__(self, current_version="1.0"):
        self.current_version = current_version

    def is_compatible(self, target_version: str) -> bool:
        """
        Checks if the target version is compatible with the current version.
        
        Args:
            target_version (str): Version to check compatibility for.
        
        Returns:
            bool: True if compatible, False otherwise.
        """
        if target_version in SUPPORTED_VERSIONS:
            logger.info(f"Version {target_version} is compatible with current version {self.current_version}.")
            return True
        elif target_version in DEPRECATED_VERSIONS:
            logger.warning(f"Version {target_version} is deprecated and may not be fully compatible.")
            return False
        else:
            logger.error(f"Version {target_version} is not supported.")
            return False

    def transform_metadata_to_version(self, metadata, target_version: str):
        """
        Transforms metadata to align with a target version, if possible.
        
        Args:
            metadata (object): Metadata to transform.
            target_version (str): Target version to transform metadata to.
        
        Returns:
            object: Transformed metadata or original metadata if no transformation is required.
        """
        if target_version == self.current_version:
            logger.debug("No transformation required; target version matches current version.")
            return metadata
        # Example transformation logic based on version
        if target_version == "1.1":
            # Add specific fields or transformations for v1.1
            logger.info("Transforming metadata to version 1.1.")
            metadata.new_field = "default_value"  # Example of adding a new field in v1.1
        else:
            logger.warning(f"No transformation logic defined for target version {target_version}.")
        
        return metadata
