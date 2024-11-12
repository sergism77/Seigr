import logging

logger = logging.getLogger(__name__)

class VisualizationHelper:
    """
    Provides utility functions for rendering `.seigr` data in a senary-centric, interactive display.
    Manages senary color mapping, canvas layouts, and multi-layered views.
    """

    def __init__(self):
        # Predefine a color map for senary values (0-5)
        self.senary_color_map = self.generate_senary_color_map()

    def generate_senary_color_map(self) -> dict:
        """
        Creates a color map where each senary digit (0-5) is mapped to a unique color.
        
        Returns:
            dict: A dictionary mapping senary values to hex color codes.
        """
        color_map = {
            0: "#FF6347",  # Tomato
            1: "#FFD700",  # Gold
            2: "#ADFF2F",  # Green Yellow
            3: "#00FA9A",  # Medium Spring Green
            4: "#1E90FF",  # Dodger Blue
            5: "#9932CC"   # Dark Orchid
        }
        logger.debug("Generated senary color map.")
        return color_map

    def map_senary_to_color(self, senary_value: int) -> str:
        """
        Maps a senary value (0-5) to its corresponding color for visualization.
        
        Args:
            senary_value (int): A senary digit (0-5).
        
        Returns:
            str: Hex color code for the corresponding senary value.
        """
        color = self.senary_color_map.get(senary_value, "#FFFFFF")  # Default to white if out of range
        logger.debug(f"Mapped senary value {senary_value} to color {color}.")
        return color

    def create_layered_view(self, data: list, depth_levels: int) -> list:
        """
        Organizes data into layered views based on the specified depth levels.
        
        Args:
            data (list): Raw data to layer.
            depth_levels (int): Number of depth levels for layering.
        
        Returns:
            list: Layered data structure for multi-level visualization.
        """
        layered_data = []
        chunk_size = max(1, len(data) // depth_levels)
        
        for i in range(0, len(data), chunk_size):
            layer = data[i:i + chunk_size]
            layered_data.append(layer)
            logger.debug(f"Created layer with {len(layer)} items at depth level {len(layered_data)}.")

        logger.info(f"Organized data into {depth_levels} layered views.")
        return layered_data

    def calculate_canvas_layout(self, num_elements: int, aspect_ratio=1.0) -> tuple:
        """
        Calculates an optimal canvas layout based on the number of elements and desired aspect ratio.
        
        Args:
            num_elements (int): Total number of elements to display.
            aspect_ratio (float): Desired aspect ratio for the layout.
        
        Returns:
            tuple: Number of rows and columns for the canvas layout.
        """
        import math
        cols = math.ceil(math.sqrt(num_elements * aspect_ratio))
        rows = math.ceil(num_elements / cols)
        logger.debug(f"Calculated canvas layout: {rows} rows, {cols} columns.")
        return rows, cols

    def generate_tooltip_content(self, segment_data: dict) -> str:
        """
        Generates content for a tooltip based on segment data.
        
        Args:
            segment_data (dict): Data for the segment being visualized.
        
        Returns:
            str: Formatted tooltip content.
        """
        content = f"Segment Index: {segment_data.get('index', 'N/A')}\n"
        content += f"Senary Values: {segment_data.get('senary_values', 'N/A')}\n"
        content += f"Created By: {segment_data.get('creator_id', 'Unknown')}\n"
        logger.debug("Generated tooltip content.")
        return content
