# config.py
import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your_secret_key")

    # Base directory for Seigr configurations and data storage
    SEIGR_DIRECTORY = os.path.expanduser("~/.seigr")

    # Paths updated to use .seigr extension
    SEIGR_ID_PATH = os.path.join(SEIGR_DIRECTORY, "seigr_id.protobuf")
    PING_LOG_PATH = os.path.join(
        SEIGR_DIRECTORY, "ping_logs.protobuf"
    )  # Updated to protobuf for ping logs

    # Other directories
    LOG_DIRECTORY = os.path.join(SEIGR_DIRECTORY, "logs")
    CLUSTER_DIRECTORY = os.path.join(SEIGR_DIRECTORY, "seed_clusters")
    UPLOAD_FOLDER = os.path.join(SEIGR_DIRECTORY, "uploads")
    SEIGR_ID_DIRECTORY = os.path.join(
        SEIGR_DIRECTORY, "test_ids"
    )  # Add a directory for identity testing

    # Ensure all necessary directories exist
    os.makedirs(SEIGR_DIRECTORY, exist_ok=True)
    os.makedirs(LOG_DIRECTORY, exist_ok=True)
    os.makedirs(CLUSTER_DIRECTORY, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(
        SEIGR_ID_DIRECTORY, exist_ok=True
    )  # Ensure test identity directory exists
