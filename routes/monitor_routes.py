# routes/monitor_routes.py
from flask import Blueprint, jsonify
import os
import json
from config import Config

bp = Blueprint('monitor_routes', __name__)

@bp.route('/get_activity_log', methods=['GET'])
def get_activity_log():
    """Returns the ping activity log for the Seigr ID."""
    if not os.path.exists(Config.PING_LOG_PATH):
        return jsonify({"error": "No activity log found"}), 404

    with open(Config.PING_LOG_PATH, 'r') as f:
        logs = [json.loads(line) for line in f.readlines()]

    return jsonify({"activity_log": logs})
