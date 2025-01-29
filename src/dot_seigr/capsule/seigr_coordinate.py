import logging
from src.crypto.hash_utils import hypha_hash
from src.seigr_protocol.compiled.coordinate_pb2 import CoordinateIndex

logger = logging.getLogger(__name__)


class SeigrCoordinateManager:
    """
    Manages and tracks multi-dimensional coordinate indexing for Seigr segments.
    Supports adaptive, multi-layered path-based hashing with dynamic validation.
    """

    def __init__(self, index: int, coordinates: dict = None, metadata: dict = None):
        """
        Initializes SeigrCoordinateManager with multi-dimensional coordinates.

        Args:
            index (int): Segment index associated with these coordinates.
            coordinates (dict, optional): Initial coordinate values (e.g., {"x": 0, "y": 0, "z": 0, "t": "2025-01-29T00:00:00Z"}).
            metadata (dict, optional): Extra metadata for flexibility.
        """
        self.index = index
        self.coordinates = CoordinateIndex()
        self.dimension_map = coordinates or {"x": 0, "y": 0, "z": 0, "t": ""}
        self.metadata = metadata or {}

        # Apply defined coordinates to `CoordinateIndex`
        for dim, value in self.dimension_map.items():
            if hasattr(self.coordinates, dim):
                setattr(self.coordinates, dim, value)
            else:
                logger.warning(
                    f"Dimension '{dim}' not recognized in CoordinateIndex; storing in metadata."
                )
                self.metadata[dim] = value  # Store unknown attributes in metadata

        # Set metadata inside CoordinateIndex
        self.coordinates.metadata.update(self.metadata)

        logger.info(
            f"Initialized SeigrCoordinateManager for segment {self.index} with coordinates: {self.dimension_map}"
        )

    def set_coordinates(self, **kwargs):
        """
        Updates coordinate values dynamically.

        Args:
            kwargs: Key-value pairs of coordinate names and values.

        Raises:
            ValueError: If attempting to set a coordinate that is unsupported in CoordinateIndex.
        """
        for dim, value in kwargs.items():
            if hasattr(self.coordinates, dim):
                setattr(self.coordinates, dim, value)
                self.dimension_map[dim] = value
            else:
                logger.warning(
                    f"Dimension '{dim}' not recognized in CoordinateIndex; storing in metadata."
                )
                self.metadata[dim] = value
                self.coordinates.metadata[dim] = str(value)  # Ensure string storage in metadata

        logger.debug(f"Updated coordinates for segment {self.index}: {self.dimension_map}")

    def get_coordinates(self) -> CoordinateIndex:
        """
        Returns the current CoordinateIndex object with all mapped dimensions.

        Returns:
            CoordinateIndex: The structured coordinate index.
        """
        logger.debug(f"Retrieved coordinates for segment {self.index}: {self.dimension_map}")
        return self.coordinates

    def generate_path_hash(self) -> str:
        """
        Generates a unique hash based on multi-dimensional coordinates.

        Returns:
            str: Hash representing the current coordinate state.
        """
        coord_values = "".join(str(value) for value in self.dimension_map.values())
        path_hash = hypha_hash(coord_values.encode())
        logger.debug(f"Generated path hash {path_hash} for coordinates: {self.dimension_map}")
        return path_hash

    def validate_coordinates(self, bounds: dict) -> bool:
        """
        Validates that each coordinate falls within defined bounds.

        Args:
            bounds (dict): Expected min/max range for each coordinate.

        Returns:
            bool: True if all values are valid, otherwise False.
        """
        for dim, (min_val, max_val) in bounds.items():
            if dim in self.dimension_map:
                value = self.dimension_map[dim]
                if isinstance(value, (int, float)) and not (min_val <= value <= max_val):
                    logger.warning(f"Coordinate {dim}={value} out of bounds ({min_val}-{max_val}).")
                    return False
        logger.info(f"All coordinates within bounds for segment {self.index}.")
        return True

    def reset_coordinates(self):
        """
        Resets all coordinates to their default values.
        """
        for dim in self.dimension_map:
            setattr(
                self.coordinates,
                dim,
                0 if isinstance(self.dimension_map[dim], (int, float)) else "",
            )

        logger.info(
            f"Coordinates reset for segment {self.index}. Current state: {self.dimension_map}"
        )
