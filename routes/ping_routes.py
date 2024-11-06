# routes/ping_routes.py
from flask import Blueprint, jsonify
from datetime import datetime
import json
from config import Config

bp = Blueprint('ping_routes', __name__)

@bp.route('/ping', methods=['POST'])
def ping():
    """Records a network ping for the Seigr ID, logging the timestamp."""
    timestamp = datetime.now().isoformat()
    ping_entry = {"timestamp": timestamp}

    # Append the new ping to the log file
    with open(Config.PING_LOG_PATH, 'a') as f:
        f.write(json.dumps(ping_entry) + "\n")
    
    return jsonify({"status": "pinged", "timestamp": timestamp})
