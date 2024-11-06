# config.py
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your_secret_key")
    SEIGR_DIRECTORY = os.path.expanduser("~/.seigr")
    SEIGR_ID_PATH = os.path.join(SEIGR_DIRECTORY, "seigr_id.json")
    LOG_DIRECTORY = os.path.join(SEIGR_DIRECTORY, "logs")
    PING_LOG_PATH = os.path.join(SEIGR_DIRECTORY, "ping_logs.json")
    CLUSTER_DIRECTORY = os.path.join(SEIGR_DIRECTORY, "seed_clusters")
    UPLOAD_FOLDER = os.path.join(SEIGR_DIRECTORY, "uploads")
    os.makedirs(SEIGR_DIRECTORY, exist_ok=True)
    os.makedirs(LOG_DIRECTORY, exist_ok=True)
    os.makedirs(CLUSTER_DIRECTORY, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
