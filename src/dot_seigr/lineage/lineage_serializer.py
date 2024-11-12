import logging
from src.seigr_protocol.compiled.lineage_pb2 import Lineage as LineageProto, LineageEntry as LineageEntryProto

logger = logging.getLogger(__name__)

class LineageSerializer:
    @staticmethod
    def to_protobuf(lineage) -> LineageProto:
        """
        Serializes a Lineage instance to a Protobuf LineageProto message.
        
        Args:
            lineage (Lineage): The Lineage instance to serialize.
        
        Returns:
            LineageProto: Serialized Protobuf message representing the lineage.
        """
        lineage_proto = LineageProto(
            creator_id=lineage.creator_id,
            current_hash=lineage.current_hash,
            version=lineage.version
        )

        for entry_data in lineage.entries:
            entry_proto = LineageSerializer.entry_to_protobuf(entry_data)
            lineage_proto.entries.append(entry_proto)

        logger.debug(f"Serialized lineage to Protobuf with creator ID {lineage.creator_id}")
        return lineage_proto

    @staticmethod
    def from_protobuf(protobuf_message: LineageProto) -> dict:
        """
        Deserializes a LineageProto message to a dictionary representing lineage data.
        
        Args:
            protobuf_message (LineageProto): The Protobuf message to deserialize.
        
        Returns:
            dict: Dictionary representation of lineage data.
        """
        try:
            entries = [
                LineageSerializer.entry_from_protobuf(entry_proto)
                for entry_proto in protobuf_message.entries
            ]

            lineage_data = {
                "creator_id": protobuf_message.creator_id,
                "current_hash": protobuf_message.current_hash,
                "version": protobuf_message.version,
                "entries": entries
            }

            logger.debug(f"Deserialized Protobuf to lineage data with creator ID {protobuf_message.creator_id}")
            return lineage_data
        except Exception as e:
            logger.error(f"Failed to deserialize LineageProto message: {e}")
            raise ValueError("Invalid Protobuf format for Lineage data.") from e

    @staticmethod
    def entry_to_protobuf(entry: dict) -> LineageEntryProto:
        """
        Converts a dictionary-based lineage entry to a LineageEntryProto message.
        
        Args:
            entry (dict): A dictionary with entry fields including 'version', 'action', 'creator_id', etc.
        
        Returns:
            LineageEntryProto: Serialized Protobuf message representing the entry.
        """
        entry_proto = LineageEntryProto(
            version=entry["version"],
            action=entry["action"],
            creator_id=entry["creator_id"],
            contributor_id=entry["contributor_id"],
            timestamp=entry["timestamp"]
        )
        entry_proto.previous_hashes.extend(entry["previous_hashes"])
        entry_proto.metadata.update(entry["metadata"])

        logger.debug(f"Serialized entry for action {entry['action']} to Protobuf")
        return entry_proto

    @staticmethod
    def entry_from_protobuf(entry_proto: LineageEntryProto) -> dict:
        """
        Deserializes a LineageEntryProto message to a dictionary representation.
        
        Args:
            entry_proto (LineageEntryProto): The Protobuf message to deserialize.
        
        Returns:
            dict: Dictionary representation of a lineage entry.
        """
        try:
            entry = {
                "version": entry_proto.version,
                "action": entry_proto.action,
                "creator_id": entry_proto.creator_id,
                "contributor_id": entry_proto.contributor_id,
                "timestamp": entry_proto.timestamp,
                "previous_hashes": list(entry_proto.previous_hashes),
                "metadata": dict(entry_proto.metadata)
            }
            logger.debug(f"Deserialized Protobuf entry for action {entry_proto.action}")
            return entry
        except Exception as e:
            logger.error(f"Failed to deserialize LineageEntryProto message: {e}")
            raise ValueError("Invalid Protobuf format for Lineage entry data.") from e
