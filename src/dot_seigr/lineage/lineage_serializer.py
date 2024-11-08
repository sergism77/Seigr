# src/dot_seigr/lineage/lineage_serializer.py

from src.dot_seigr.seigr_protocol.lineage_pb2 import Lineage as LineageProto, LineageEntry as LineageEntryProto

class LineageSerializer:
    @staticmethod
    def to_protobuf(lineage) -> LineageProto:
        """
        Serializes a Lineage instance to a Protobuf message.
        
        Args:
            lineage (Lineage): The Lineage instance to serialize.
        
        Returns:
            LineageProto: Protobuf message representing the lineage.
        """
        lineage_proto = LineageProto(
            creator_id=lineage.creator_id,
            current_hash=lineage.current_hash,
            version=lineage.version
        )
        
        for entry_data in lineage.entries:
            entry_proto = LineageEntryProto(
                version=entry_data["version"],
                action=entry_data["action"],
                creator_id=entry_data["creator_id"],
                contributor_id=entry_data["contributor_id"],
                timestamp=entry_data["timestamp"]
            )
            entry_proto.previous_hashes.extend(entry_data["previous_hashes"])
            entry_proto.metadata.update(entry_data["metadata"])
            lineage_proto.entries.append(entry_proto)
        
        return lineage_proto

    @staticmethod
    def from_protobuf(protobuf_message: LineageProto) -> dict:
        """
        Deserializes a Protobuf message into a dictionary representing lineage data.
        
        Args:
            protobuf_message (LineageProto): The Protobuf message to deserialize.
        
        Returns:
            dict: Dictionary representation of lineage data.
        """
        entries = []
        for entry_proto in protobuf_message.entries:
            entry = {
                "version": entry_proto.version,
                "action": entry_proto.action,
                "creator_id": entry_proto.creator_id,
                "contributor_id": entry_proto.contributor_id,
                "timestamp": entry_proto.timestamp,
                "previous_hashes": list(entry_proto.previous_hashes),
                "metadata": dict(entry_proto.metadata)
            }
            entries.append(entry)

        return {
            "creator_id": protobuf_message.creator_id,
            "current_hash": protobuf_message.current_hash,
            "version": protobuf_message.version,
            "entries": entries
        }

    @staticmethod
    def entry_to_protobuf(entry: dict) -> LineageEntryProto:
        entry_proto = LineageEntryProto(
            version=entry["version"],
            action=entry["action"],
            creator_id=entry["creator_id"],
            contributor_id=entry["contributor_id"],
            timestamp=entry["timestamp"]
        )
        entry_proto.previous_hashes.extend(entry["previous_hashes"])
        entry_proto.metadata.update(entry["metadata"])
        return entry_proto

    @staticmethod
    def entry_from_protobuf(entry_proto: LineageEntryProto) -> dict:
        return {
            "version": entry_proto.version,
            "action": entry_proto.action,
            "creator_id": entry_proto.creator_id,
            "contributor_id": entry_proto.contributor_id,
            "timestamp": entry_proto.timestamp,
            "previous_hashes": list(entry_proto.previous_hashes),
            "metadata": dict(entry_proto.metadata)
        }
