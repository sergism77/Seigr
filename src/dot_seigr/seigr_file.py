import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.dot_seigr.seigr_constants import HEADER_SIZE, SEIGR_VERSION
from src.crypto.encoding_utils import encode_to_senary
from src.dot_seigr.seigr_protocol.manager import LinkManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import (
    SeigrFile as SeigrFileProto, TemporalLayer, FileMetadata, SegmentMetadata, AccessContext, CoordinateIndex
)

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        """
        Initializes a SeigrFile instance using protocol-compliant structures.

        Args:
            data (bytes): Raw data for the segment.
            creator_id (str): Unique identifier for the creator.
            index (int): The segment index in the original file sequence.
            file_type (str): File format type (default: "senary").
        """
        self.hypha_crypt = HyphaCrypt(data=data, segment_id=str(index))
        self.data = encode_to_senary(data)
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.hash = self.hypha_crypt.compute_primary_hash()

        # Initialize metadata and link manager
        self.metadata = self._initialize_metadata()
        self.link_manager = LinkManager()

        # Initialize temporal layers and access context
        self.temporal_layers = []
        self.access_context = AccessContext(access_count=0, last_accessed="", node_access_history=[])

    def _initialize_metadata(self) -> FileMetadata:
        """
        Initializes FileMetadata with default values.

        Returns:
            FileMetadata: Populated metadata.
        """
        creation_timestamp = datetime.now(timezone.utc).isoformat()
        metadata = FileMetadata(
            version=SEIGR_VERSION,
            creator_id=self.creator_id,
            original_filename=f"{self.creator_id}_{self.index}",
            original_extension=self.file_type,
            file_hash=self.hash,
            creation_timestamp=creation_timestamp,
            total_segments=1  # Single segment initialization
        )
        logger.debug(f"Initialized file metadata for segment {self.index} with hash {self.hash}")
        return metadata

    def set_links(self, primary_link: str, secondary_links: list):
        """
        Sets primary and secondary links using LinkManager.

        Args:
            primary_link (str): Primary hash link.
            secondary_links (list): Secondary hash links.
        """
        self.link_manager.update_links(primary_link, secondary_links)
        logger.debug(f"Set primary link to {primary_link} with secondary links: {secondary_links}")

    def add_temporal_layer(self):
        """
        Adds a new temporal layer snapshot to the .seigr file.
        """
        layer_timestamp = datetime.now(timezone.utc).isoformat()
        combined_hash = self.hypha_crypt.compute_primary_hash()
        
        temp_layer = TemporalLayer(
            timestamp=layer_timestamp,
            layer_hash=combined_hash
        )

        segment_metadata = SegmentMetadata(
            version=self.metadata.version,
            creator_id=self.creator_id,
            segment_index=self.index,
            segment_hash=self.hash,
            timestamp=layer_timestamp
        )

        temp_layer.segments.append(segment_metadata)
        self.temporal_layers.append(temp_layer)
        logger.info(f"New temporal layer added with timestamp {layer_timestamp} and hash {combined_hash}")

    def record_access(self, node_id: str):
        """
        Records access in the access context for replication scaling.

        Args:
            node_id (str): Unique identifier of the accessing node.
        """
        self.access_context.access_count += 1
        self.access_context.last_accessed = datetime.now(timezone.utc).isoformat()
        self.access_context.node_access_history.append(node_id)
        logger.debug(f"Access recorded for node {node_id}. Total access count: {self.access_context.access_count}")

    def save_to_disk(self, base_dir: str) -> str:
        """
        Saves the .seigr file as a protobuf binary file.

        Args:
            base_dir (str): Directory where the file will be saved.

        Returns:
            str: Path to the saved file.
        """
        filename = f"{self.creator_id}_{self.index}.seigr.pb"
        file_path = os.path.join(base_dir, filename)
        logger.debug(f"Preparing to save .seigr file: {filename}")

        try:
            seigr_file_proto = SeigrFileProto()
            seigr_file_proto.metadata.CopyFrom(self.metadata)
            seigr_file_proto.data = self.data

            # Populate temporal layers
            for layer in self.temporal_layers:
                temp_layer_proto = seigr_file_proto.temporal_layers.add()
                temp_layer_proto.timestamp = layer.timestamp
                temp_layer_proto.layer_hash = layer.layer_hash
                temp_layer_proto.segments.extend(layer.segments)

            # Populate access context
            seigr_file_proto.access_context.CopyFrom(self.access_context)

            # Populate links
            links = self.link_manager.get_links()
            seigr_file_proto.links.primary_link = links["primary"]
            seigr_file_proto.links.secondary_links.extend(links["secondary"])

            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(seigr_file_proto.SerializeToString())

            logger.info(f".seigr file saved at {file_path}")
            return file_path

        except (TypeError, ValueError, IOError) as e:
            logger.error(f"Failed to save .seigr file at {file_path}: {e}")
            raise

    def add_coordinate_index(self, x: int, y: int, z: int):
        """
        Adds a 3D coordinate index for data positioning.

        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        coord_index = CoordinateIndex(x=x, y=y, z=z)
        self.metadata.coordinate_index.CopyFrom(coord_index)
        logger.debug(f"Coordinate index set to x: {x}, y: {y}, z: {z}")
