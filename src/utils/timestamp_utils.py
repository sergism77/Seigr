from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime, timezone


def get_protobuf_timestamp(dt: datetime) -> Timestamp:
    """Convert a Python datetime object to a Protobuf Timestamp."""
    if not isinstance(dt, datetime):
        raise TypeError(f"Expected datetime, got {type(dt).__name__}")

    ts = Timestamp()
    ts.FromDatetime(dt.astimezone(timezone.utc))  # Ensure UTC
    return ts


def from_protobuf_timestamp(ts: Timestamp) -> datetime:
    """Convert a Protobuf Timestamp to a Python datetime object."""
    if not isinstance(ts, Timestamp):
        raise TypeError(f"Expected Timestamp, got {type(ts).__name__}")

    return ts.ToDatetime().replace(tzinfo=timezone.utc)


def get_current_protobuf_timestamp() -> Timestamp:
    """Return the current UTC time as a Protobuf Timestamp."""
    return get_protobuf_timestamp(datetime.now(timezone.utc))


def from_iso_string_to_protobuf(iso_str: str) -> Timestamp:
    """Convert an ISO 8601 formatted string to a Protobuf Timestamp."""
    try:
        dt = datetime.fromisoformat(iso_str).replace(tzinfo=timezone.utc)
        return get_protobuf_timestamp(dt)
    except ValueError as e:
        raise ValueError(f"Invalid ISO format string: {iso_str}") from e


def from_json_string_to_protobuf(json_timestamp: str) -> Timestamp:
    """Convert a JSON timestamp string to a Protobuf Timestamp."""
    if not isinstance(json_timestamp, str):
        raise TypeError(f"Expected string, got {type(json_timestamp).__name__}")

    ts = Timestamp()
    try:
        ts.FromJsonString(json_timestamp)
    except ValueError as e:
        raise ValueError(f"Invalid JSON timestamp string: {json_timestamp}") from e

    return ts
