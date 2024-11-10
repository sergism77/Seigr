import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_constants import SEIGR_VERSION
from dot_seigr.file_format.seigr_metadata_manager import MetadataManager
from src.dot_seigr.access_control import AccessControlManager
from src.dot_seigr.temporal_layer_manager import TemporalLayerManager
from dot_seigr.file_format.seigr_coordinate import CoordinateManager
from src.dot_seigr.serialization_manager import SerializationManager
from dot_seigr.file_format.seigr_link_manager import LinkManager
from dot_seigr.file_format.seigr_integrity_manager import IntegrityManager

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        self.data = data
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type

        # Modular components
        self.hypha_crypt = HyphaCrypt(data, str(index), use_senary=(file_type == "senary"))
        self.metadata_manager = MetadataManager(self.creator_id, self.index, self.file_type)
        self.access_control = AccessControlManager(self.creator_id)
        self.temporal_layers = TemporalLayerManager(self.index)
        self.coordinate_manager = CoordinateManager(self.index)
        self.serialization = SerializationManager()
        self.link_manager = LinkManager()
        self.integrity_manager = IntegrityManager(self.data, self.hypha_crypt)

    def generate_metadata(self):
        self.metadata = self.metadata_manager.generate_metadata(self.hypha_crypt)
        logger.debug(f"Metadata initialized: {self.metadata}")

    def set_links(self, primary_link, secondary_links):
        self.link_manager.set_links(primary_link, secondary_links)

    def add_temporal_layer(self):
        self.temporal_layers.add_layer(self.metadata, self.data)

    def add_coordinate_index(self, x, y, z):
        self.coordinate_manager.set_coordinates(x, y, z)

    def compute_integrity(self):
        self.integrity_manager.compute_integrity(self.metadata_manager.get_metadata())

    def save_to_disk(self, base_dir, use_cbor=False):
        return self.serialization.save(self, base_dir, use_cbor)
