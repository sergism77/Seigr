import logging
from .lineage_serializer import LineageSerializer
from src.dot_seigr.seigr_protocol.lineage_pb2 import Lineage as LineageProto

logger = logging.getLogger(__name__)

class LineageStorage:
    @staticmethod
    def save_to_disk(lineage, storage_path: str):
        try:
            lineage_proto = LineageSerializer.to_protobuf(lineage)
            with open(storage_path, 'wb') as f:
                f.write(lineage_proto.SerializeToString())
            logger.info(f"Lineage saved successfully at {storage_path}")
        except IOError as e:
            logger.error(f"Failed to save lineage to {storage_path}: {e}")
            raise

    @staticmethod
    def load_from_disk(storage_path: str):
        lineage_proto = LineageProto()
        try:
            with open(storage_path, 'rb') as f:
                lineage_proto.ParseFromString(f.read())
            return LineageSerializer.from_protobuf(lineage_proto)
        except (IOError, ValueError) as e:
            logger.error(f"Failed to load lineage from {storage_path}: {e}")
            raise
