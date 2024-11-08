import os
import logging
import cbor2
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_constants import HEADER_SIZE, SEIGR_VERSION
from src.crypto.encoding_utils import encode_to_senary
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import (
    SeedDotSeigr,  # Previously SeedDotSeigr
    SegmentMetadata,
    FileMetadata,
    TemporalLayer,
    AccessContext,
    CoordinateIndex
)


from src.dot_seigr.seigr_protocol.manager import LinkManager

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        """
        Initializes a SeigrFile instance using protocol-compliant structures.
        """
        # Set up encryption and data encoding
        self.hypha_crypt = HyphaCrypt(data=data, segment_id=str(index), use_senary=(file_type == "senary"))
        self.data = encode_to_senary(data) if file_type == "senary" else data.hex()
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.hash = self.hypha_crypt.compute_primary_hash()
        self.data_hash = hypha_hash(data)

        # Initialize metadata and link manager
        self.metadata = self._initialize_metadata()  # Ensure metadata is assigned to self.metadata
        self.link_manager = LinkManager()

        # Initialize temporal layers and access context
        self.temporal_layers = []
        self.access_context = self._initialize_access_context()
    
    def _initialize_metadata(self) -> SegmentMetadata:
        """
        Initializes SegmentMetadata with default values, including the data hash for integrity.
        
        Returns:
            SegmentMetadata: Populated metadata with data hash.
        """
        creation_timestamp = datetime.now(timezone.utc).isoformat()
        metadata = SegmentMetadata(
            version=SEIGR_VERSION,
            creator_id=self.creator_id,
            segment_index=self.index,
            segment_hash=self.hash,
            timestamp=creation_timestamp,
            data_hash=self.data_hash  # Store data hash for integrity checks
        )
        logger.debug(f"Initialized metadata for segment {self.index} with hash {self.hash} and data_hash {self.data_hash}")
        return metadata

    def _initialize_access_context(self) -> AccessContext:
        """Initializes the access context with default values."""
        return AccessContext(access_count=0, last_accessed="", node_access_history=[])

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

        # Populate SegmentMetadata for temporal layer
        segment_metadata = SegmentMetadata(
            version=self.metadata.version,
            creator_id=self.creator_id,
            segment_index=self.index,
            segment_hash=self.hash,
            timestamp=layer_timestamp,
            data_hash=self.data_hash
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

    def save_to_disk(self, base_dir: str, use_cbor: bool = False) -> str:
        """
        Saves the .seigr file as a serialized file (CBOR or Protobuf).
        
        Args:
            base_dir (str): Directory where the file will be saved.
            use_cbor (bool): Whether to save in CBOR format.
        
        Returns:
            str: Path to the saved file.
        """
        filename = f"{self.creator_id}_{self.index}.seigr.{'cbor' if use_cbor else 'pb'}"
        file_path = os.path.join(base_dir, filename)
        logger.debug(f"Preparing to save .seigr file: {filename}")

        try:
            if use_cbor:
                file_data = self._serialize_to_cbor()
            else:
                file_data = self._serialize_to_protobuf()

            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file_data)

            logger.info(f".seigr file saved at {file_path}")
            return file_path

        except (TypeError, ValueError, IOError) as e:
            logger.error(f"Failed to save .seigr file at {file_path}: {e}")
            raise

    def _serialize_to_protobuf(self) -> bytes:
        """
        Serializes the .seigr file to Protobuf format.
        
        Returns:
            bytes: Protobuf-encoded data.
        """
        seigr_file_proto = SeedDotSeigr()
        
        # Set primary fields in SeedDotSeigr
        seigr_file_proto.root_hash = self.hash
        seigr_file_proto.seed_hash = self.metadata.segment_hash
        seigr_file_proto.creation_timestamp = self.metadata.timestamp
        seigr_file_proto.version = SEIGR_VERSION
        
        # Populate file metadata
        file_metadata = FileMetadata(
            version=self.metadata.version,
            creator_id=self.metadata.creator_id,
            file_hash=self.metadata.segment_hash,
            creation_timestamp=self.metadata.timestamp,
            total_segments=self.index
        )
        seigr_file_proto.file_metadata.CopyFrom(file_metadata)
        
        # Populate temporal layers
        seigr_file_proto.temporal_layers.extend(self.temporal_layers)
        
        # Populate access context
        seigr_file_proto.file_metadata.access_context.CopyFrom(self.access_context)
        
        # Populate link data in SegmentMetadata
        links = self.link_manager.get_links()
        segment_metadata = SegmentMetadata(
            segment_index=self.index,
            segment_hash=self.hash,
            primary_link=links["primary"]
        )
        segment_metadata.secondary_links.extend(links["secondary"])
        
        # Add segment metadata to segments in SeedDotSeigr
        seigr_file_proto.segments.append(segment_metadata)

        return seigr_file_proto.SerializeToString()

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

    def _serialize_to_cbor(self) -> bytes:
        """
        Serializes the .seigr file to CBOR format.

        Returns:
            bytes: CBOR-encoded data.
        """
        # Prepare dictionary for CBOR serialization
        seigr_file_dict = {
            "metadata": {
                "version": self.metadata.version,
                "creator_id": self.metadata.creator_id,
                "segment_index": self.metadata.segment_index,
                "segment_hash": self.metadata.segment_hash,
                "timestamp": self.metadata.timestamp,
                "data_hash": self.metadata.data_hash
            },
            "data": self.data,
            "temporal_layers": [
                {
                    "timestamp": layer.timestamp,
                    "layer_hash": layer.layer_hash,
                    "segments": [
                        {
                            "version": seg.version,
                            "creator_id": seg.creator_id,
                            "segment_index": seg.segment_index,
                            "segment_hash": seg.segment_hash,
                            "timestamp": seg.timestamp,
                            "data_hash": seg.data_hash
                        } for seg in layer.segments
                    ]
                } for layer in self.temporal_layers
            ],
            "access_context": {
                "access_count": self.access_context.access_count,
                "last_accessed": self.access_context.last_accessed,
                "node_access_history": list(self.access_context.node_access_history)
            },
            "links": self.link_manager.get_links()
        }
        return cbor2.dumps(seigr_file_dict)