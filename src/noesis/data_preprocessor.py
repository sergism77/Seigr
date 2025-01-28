import logging
from typing import List, Dict, Any
from google.protobuf.json_format import ParseDict, MessageToDict
from src.seigr_protocol.compiled.noesis_pb2 import NoesisTask
from datetime import datetime, timezone

# Initialize logger
logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Handles preprocessing of data for the Seigr ecosystem, ensuring compatibility with
    `.seigr` files and Seigr protocol buffers, including validation, cleaning, and normalization.

    Attributes:
        schema (type): The expected schema for input data (e.g., NoesisTask).
    """

    def __init__(self):
        """
        Initializes the DataPreprocessor with default settings.
        """
        self.schema = NoesisTask
        logger.info("DataPreprocessor initialized successfully.")

    def validate_data(self, data: Dict[str, Any]) -> bool:
        """
        Validates the input data against the expected protocol buffer schema.

        Args:
            data (Dict[str, Any]): The input data as a dictionary.

        Returns:
            bool: True if the data is valid, False otherwise.
        """
        try:
            # Parse the dictionary into a NoesisTask object to validate
            ParseDict(data, self.schema())
            logger.debug("Data validation successful.")
            return True
        except Exception as e:
            logger.error(f"Data validation failed: {e}")
            return False

    def clean_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Cleans the input data by removing invalid or duplicate entries.

        Args:
            data (List[Dict[str, Any]]): A list of input data dictionaries.

        Returns:
            List[Dict[str, Any]]: Cleaned data.
        """
        logger.info("Starting data cleaning process.")
        cleaned_data = []
        seen_hashes = set()

        for entry in data:
            try:
                # Validate the entry
                if not self.validate_data(entry):
                    continue

                # Generate a hash to detect duplicates
                entry_hash = hash(frozenset(entry.items()))
                if entry_hash in seen_hashes:
                    logger.warning("Duplicate entry detected and removed.")
                    continue

                seen_hashes.add(entry_hash)
                cleaned_data.append(entry)

            except Exception as e:
                logger.error(f"Error during data cleaning: {e}")
                continue

        logger.info(f"Data cleaning completed. {len(cleaned_data)} valid entries retained.")
        return cleaned_data

    def normalize_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalizes the input data, ensuring values are scaled and timestamps standardized.

        Args:
            data (List[Dict[str, Any]]): A list of input data dictionaries.

        Returns:
            List[Dict[str, Any]]: Normalized data.
        """
        logger.info("Starting data normalization process.")
        normalized_data = []

        for entry in data:
            try:
                # Normalize numeric values (e.g., scale from 0-1)
                for key, value in entry.items():
                    if isinstance(value, (int, float)):
                        entry[key] = self._normalize_numeric(value)

                    # Standardize datetime values to ISO 8601 format
                    if isinstance(value, str) and self._is_datetime(value):
                        entry[key] = self._normalize_datetime(value)

                normalized_data.append(entry)

            except Exception as e:
                logger.error(f"Error during data normalization: {e}")
                continue

        logger.info("Data normalization completed.")
        return normalized_data

    def preprocess(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        End-to-end preprocessing pipeline: validation, cleaning, and normalization.

        Args:
            raw_data (List[Dict[str, Any]]): A list of raw data dictionaries.

        Returns:
            List[Dict[str, Any]]: Fully preprocessed data.
        """
        logger.info("Starting full preprocessing pipeline.")
        # Step 1: Clean the data
        cleaned_data = self.clean_data(raw_data)

        # Step 2: Normalize the data
        normalized_data = self.normalize_data(cleaned_data)

        logger.info("Preprocessing pipeline completed.")
        return normalized_data

    def _normalize_numeric(self, value: float) -> float:
        """
        Normalizes a numeric value to a range of 0 to 1.

        Args:
            value (float): The numeric value to normalize.

        Returns:
            float: Normalized numeric value.
        """
        min_value, max_value = 0.0, 100.0  # Example normalization range
        normalized = (value - min_value) / (max_value - min_value)
        logger.debug(f"Normalized numeric value: {value} -> {normalized}")
        return normalized

    def _normalize_datetime(self, value: str) -> str:
        """
        Converts a datetime string into ISO 8601 format.

        Args:
            value (str): The datetime string to normalize.

        Returns:
            str: Normalized datetime string in ISO 8601 format.
        """
        try:
            dt = datetime.fromisoformat(value)
            normalized_dt = dt.astimezone(timezone.utc).isoformat()
            logger.debug(f"Normalized datetime: {value} -> {normalized_dt}")
            return normalized_dt
        except Exception as e:
            logger.warning(f"Invalid datetime format for value '{value}': {e}")
            raise

    def _is_datetime(self, value: str) -> bool:
        """
        Checks if a string is a valid datetime format.

        Args:
            value (str): The string to check.

        Returns:
            bool: True if the string is a valid datetime, False otherwise.
        """
        try:
            datetime.fromisoformat(value)
            return True
        except ValueError:
            return False
