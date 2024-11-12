import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Formatter:
    """
    Provides utilities for formatting `.seigr` data, metadata, and logs for display.
    Ensures data is structured in a human-readable, browser-compatible format.
    """

    @staticmethod
    def format_metadata_for_display(metadata) -> dict:
        """
        Formats `.seigr` metadata into a JSON-friendly dictionary for display.
        
        Args:
            metadata (object): Metadata object to format.
        
        Returns:
            dict: Formatted metadata ready for UI display.
        """
        display_data = {
            "creator_id": metadata.creator_id,
            "file_name": metadata.file_name,
            "created_at": Formatter.format_timestamp(metadata.creation_timestamp),
            "version": metadata.version,
            "file_hash": metadata.file_hash,
            "segment_count": getattr(metadata, "segment_count", 0),
            "access_log": Formatter.format_access_log(metadata.access_control_list.entries)
        }
        logger.debug("Formatted metadata for display.")
        return display_data

    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """
        Converts a timestamp into a human-readable format.
        
        Args:
            timestamp (str): ISO format timestamp string.
        
        Returns:
            str: Formatted timestamp.
        """
        try:
            dt = datetime.fromisoformat(timestamp)
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            logger.debug(f"Formatted timestamp: {formatted_time}")
            return formatted_time
        except ValueError:
            logger.error("Invalid timestamp format.")
            return timestamp

    @staticmethod
    def format_segment_summary(segment) -> dict:
        """
        Formats a segment's summary data for quick display.
        
        Args:
            segment (object): Segment object to summarize.
        
        Returns:
            dict: JSON-friendly summary of the segment.
        """
        summary = {
            "index": segment.segment_index,
            "hash": segment.segment_hash,
            "timestamp": Formatter.format_timestamp(segment.timestamp),
            "creator_id": segment.creator_id
        }
        logger.debug(f"Formatted segment summary for index {segment.segment_index}.")
        return summary

    @staticmethod
    def format_access_log(log_entries) -> list:
        """
        Formats access log entries for display in a readable format.
        
        Args:
            log_entries (list): List of access log entries.
        
        Returns:
            list: Formatted access log entries.
        """
        formatted_entries = []
        for entry in log_entries:
            formatted_entry = {
                "user_id": entry.user_id,
                "access_time": Formatter.format_timestamp(entry.access_time),
                "permission_level": entry.permission_level
            }
            formatted_entries.append(formatted_entry)
        logger.debug("Formatted access log entries.")
        return formatted_entries
