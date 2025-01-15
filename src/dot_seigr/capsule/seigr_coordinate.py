import logging

from src.crypto.hash_utils import hypha_hash
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import CoordinateIndex

logger = logging.getLogger(__name__)


class SeigrCoordinateManager:
    """
    Manages and tracks multi-dimensional coordinate indexing for Seigr segments,
    supporting adaptive, multi-layered path-based hashing with dynamic dimension handling.
    """

    def __init__(self, index: int, dimensions: dict = None):
        """
        Initializes SeigrCoordinateManager to manage custom, multi-dimensional coordinates.

        Args:
            index (int): Segment index associated with these coordinates.
            dimensions (dict): Initial set of dimensions (e.g., {"x": 0, "y": 0, "layer": 1}).
        """
        self.index = index
        self.coordinates = CoordinateIndex()
        self.dimension_map = (
            dimensions if dimensions else {"x": 0, "y": 0, "z": 0}
        )  # Default to 3D coordinates

        # Apply dimensions to CoordinateIndex, dynamically mapping each dimension
        for dim, value in self.dimension_map.items():
            if hasattr(self.coordinates, dim):
                setattr(self.coordinates, dim, value)
            else:
                logger.warning(
                    f"Dimension '{dim}' not in CoordinateIndex; initializing with default."
                )

        logger.info(
            f"Initialized SeigrCoordinateManager for segment {self.index} with dimensions: {self.dimension_map}"
        )

    def set_coordinates(self, **kwargs):
        """
        Sets or updates coordinates dynamically across multiple dimensions.

        Args:
            kwargs: Key-value pairs of dimension names and values (e.g., x=1, y=2, z=3, layer=1).

        Raises:
            ValueError: If attempting to set a dimension that is unsupported in CoordinateIndex.
        """
        for dim, value in kwargs.items():
            if not hasattr(self.coordinates, dim):
                raise ValueError(f"Dimension '{dim}' not supported in CoordinateIndex.")
            setattr(self.coordinates, dim, value)
            self.dimension_map[dim] = value

        logger.debug(f"Coordinates updated for segment {self.index}: {self.dimension_map}")

    def get_coordinates(self) -> CoordinateIndex:
        """
        Returns the current CoordinateIndex object with all active dimensions.

        Returns:
            CoordinateIndex: Current coordinate index with mapped dimensions.
        """
        logger.debug(f"Retrieved coordinates for segment {self.index}: {self.dimension_map}")
        return self.coordinates

    def generate_path_hash(self) -> str:
        """
        Generates a unique hash based on the multi-dimensional coordinates for secure routing.

        Returns:
            str: A hash representing the unique path based on current coordinates.
        """
        coord_values = "".join(str(value) for value in self.dimension_map.values())
        path_hash = hypha_hash(coord_values.encode())
        logger.debug(f"Generated path hash {path_hash} for coordinates: {self.dimension_map}")
        return path_hash

    def validate_coordinates(self, bounds: dict) -> bool:
        """
        Validates that each coordinate falls within its defined bounds.

        Args:
            bounds (dict): Dictionary defining min and max values for each dimension,
                           e.g., {"x": (0, 100), "y": (0, 100), "layer": (0, 10)}

        Returns:
            bool: True if all coordinates are within specified bounds, False otherwise.
        """
        for dim, (min_val, max_val) in bounds.items():
            coord_value = getattr(self.coordinates, dim, None)
            if coord_value is None or not (min_val <= coord_value <= max_val):
                logger.warning(
                    f"Coordinate {dim}={coord_value} out of bounds for segment {self.index}. Expected within {min_val}-{max_val}."
                )
                return False
        logger.info(f"All coordinates within bounds for segment {self.index}.")
        return True

    def extend_dimension(self, dim_name: str, initial_value: int = 0):
        """
        Dynamically adds a new dimension to the coordinate structure.

        Args:
            dim_name (str): Name of the new dimension.
            initial_value (int): Initial value for the new dimension.

        Raises:
            ValueError: If the dimension already exists.
        """
        if hasattr(self.coordinates, dim_name):
            raise ValueError(f"Dimension '{dim_name}' already exists in CoordinateIndex.")

        setattr(self.coordinates, dim_name, initial_value)
        self.dimension_map[dim_name] = initial_value
        logger.info(
            f"Extended coordinates for segment {self.index} with new dimension '{dim_name}' set to {initial_value}."
        )

    def reset_coordinates(self):
        """
        Resets all coordinates to initial values, preserving structure but clearing values.
        """
        for dim in self.dimension_map:
            setattr(self.coordinates, dim, 0)
        logger.info(
            f"Coordinates reset for segment {self.index}. Current state: {self.dimension_map}"
        )
