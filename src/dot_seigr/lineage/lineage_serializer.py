# src/dot_seigr/lineage/lineage_serializer.py

import logging
from typing import Any, Dict

# ✅ Correctly re-aligned imports
from src.seigr_protocol.compiled.lineage_pb2 import Lineage as LineageProto
from src.seigr_protocol.compiled.common_pb2 import LineageEntry as LineageEntryProto
from src.logger.secure_logger import secure_logger


class LineageSerializer:
    """
    Handles the serialization and deserialization of Lineage data to and from Protobuf messages.
    """

    @staticmethod
    def to_protobuf(lineage) -> LineageProto:
        """
        Serializes a Lineage instance to a Protobuf LineageProto message.

        Args:
            lineage (Lineage): The Lineage instance to serialize.

        Returns:
            LineageProto: Serialized Protobuf message representing the lineage.
        """
        try:
            lineage_proto = LineageProto(
                creator_id=lineage.creator_id,
                current_hash=lineage.current_hash,
                version=lineage.version,
            )

            for entry_data in lineage.entries:
                entry_proto = LineageSerializer.entry_to_protobuf(entry_data)
                lineage_proto.entries.append(entry_proto)

            secure_logger.log_audit_event(
                "debug",
                "LineageSerializer",
                f"✅ Serialized lineage to Protobuf with creator ID {lineage.creator_id}",
            )
            return lineage_proto
        except Exception as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Failed to serialize lineage to Protobuf: {e}"
            )
            raise ValueError("Serialization error in LineageSerializer.") from e

    @staticmethod
    def from_protobuf(protobuf_message: LineageProto) -> Dict[str, Any]:
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
                "entries": entries,
            }

            secure_logger.log_audit_event(
                "debug",
                "LineageSerializer",
                f"✅ Deserialized Protobuf to lineage data with creator ID {protobuf_message.creator_id}",
            )
            return lineage_data
        except Exception as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Failed to deserialize LineageProto message: {e}"
            )
            raise ValueError("Invalid Protobuf format for Lineage data.") from e

    @staticmethod
    def entry_to_protobuf(entry: Dict[str, Any]) -> LineageEntryProto:
        """
        Converts a dictionary-based lineage entry to a LineageEntryProto message.

        Args:
            entry (dict): A dictionary with entry fields including 'version', 'action', 'creator_id', etc.

        Returns:
            LineageEntryProto: Serialized Protobuf message representing the entry.
        """
        try:
            entry_proto = LineageEntryProto(
                version=entry["version"],
                action=entry["action"],
                creator_id=entry["creator_id"],
                contributor_id=entry["contributor_id"],
                timestamp=entry["timestamp"],
            )
            entry_proto.previous_hashes.extend(entry["previous_hashes"])
            entry_proto.metadata.update(entry["metadata"])

            secure_logger.log_audit_event(
                "debug",
                "LineageSerializer",
                f"✅ Serialized entry for action {entry['action']} to Protobuf",
            )
            return entry_proto
        except KeyError as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Missing required field in lineage entry: {e}"
            )
            raise ValueError(f"Missing required field: {e}") from e
        except Exception as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Error serializing lineage entry: {e}"
            )
            raise ValueError("Serialization error in LineageSerializer.") from e

    @staticmethod
    def entry_from_protobuf(entry_proto: LineageEntryProto) -> Dict[str, Any]:
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
                "metadata": dict(entry_proto.metadata),
            }
            secure_logger.log_audit_event(
                "debug",
                "LineageSerializer",
                f"✅ Deserialized Protobuf entry for action {entry_proto.action}",
            )
            return entry
        except KeyError as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Missing required field in deserialization: {e}"
            )
            raise ValueError(f"Missing required field: {e}") from e
        except Exception as e:
            secure_logger.log_audit_event(
                "error", "LineageSerializer", f"❌ Error deserializing lineage entry: {e}"
            )
            raise ValueError("Invalid Protobuf format for Lineage entry data.") from e
