# src/dot_seigr/compression.py
import zlib
import logging
from ..crypto.hypha_crypt import SenaryEncoderDecoder

logger = logging.getLogger(__name__)
encoder = SenaryEncoderDecoder()

def compress_data(data: bytes) -> bytes:
    """Compresses data using zlib."""
    try:
        compressed_data = zlib.compress(data)
        logger.debug("Data compressed successfully.")
        return compressed_data
    except Exception as e:
        logger.error(f"Data compression failed: {e}")
        raise

def encode_data(compressed_data: bytes) -> str:
    """Encodes compressed data to senary format."""
    try:
        senary_data = encoder.encode_to_senary(compressed_data)
        logger.debug("Data encoded to senary successfully.")
        return senary_data
    except Exception as e:
        logger.error(f"Data encoding failed: {e}")
        raise
