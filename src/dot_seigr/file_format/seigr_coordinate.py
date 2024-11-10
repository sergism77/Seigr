# src/dot_seigr/file_format/seigr_coordinate.py

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import CoordinateIndex

class SeigrCoordinateManager:
    def __init__(self, index):
        """
        Initializes a SeigrCoordinateManager to manage and track 3D coordinate indexing.
        
        Args:
            index (int): Segment index associated with these coordinates.
        """
        self.index = index
        self.coordinates = CoordinateIndex()  # Initialize as CoordinateIndex object

    def set_coordinates(self, x: int, y: int, z: int):
        """
        Sets 3D coordinates and updates the CoordinateIndex structure.

        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.coordinates.x = x
        self.coordinates.y = y
        self.coordinates.z = z

    def get_coordinates(self) -> CoordinateIndex:
        """
        Returns the current CoordinateIndex.

        Returns:
            CoordinateIndex: The current coordinate index object.
        """
        return self.coordinates
