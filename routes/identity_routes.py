# routes/identity_routes.py
from flask import Blueprint, jsonify, request
from src.identity.seigr_identity import SeigrIdentity
from config import Config
import os
import json
import logging

bp = Blueprint('identity_routes', __name__)
logger = logging.getLogger(__name__)

@bp.route('/create_seigr_id', methods=['POST'])
def create_seigr_id():
    """Generates a new Seigr ID and saves it securely in the user's local .seigr directory."""
    try:
        data = request.get_json()
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password is required to create Seigr ID"}), 400

        seigr_identity = SeigrIdentity()
        seigr_id = seigr_identity.generate_seigr_id()
        seigr_identity.set_encryption_key(password=password)

        # Define the path to save the Seigr ID
        if not os.path.exists(Config.SEIGR_ID_DIRECTORY):
            os.makedirs(Config.SEIGR_ID_DIRECTORY)
        seigr_id_path = os.path.join(Config.SEIGR_ID_DIRECTORY, "seigr_id.json")

        seigr_identity.save_to_external(seigr_id_path)

        logger.info("Seigr ID created and saved successfully.")
        return jsonify({"status": "success", "seigr_id": seigr_id})
    except Exception as e:
        logger.error(f"Failed to create Seigr ID: {e}")
        return jsonify({"error": "Failed to create Seigr ID"}), 500

@bp.route('/get_seigr_id', methods=['POST'])
def get_seigr_id():
    """Retrieves and decrypts the Seigr ID from the local storage if available."""
    try:
        data = request.get_json()
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password is required to retrieve Seigr ID"}), 400

        seigr_identity = SeigrIdentity()
        seigr_id_path = os.path.join(Config.SEIGR_ID_DIRECTORY, "seigr_id.json")

        if os.path.exists(seigr_id_path):
            if seigr_identity.load_from_external(seigr_id_path, password=password):
                return jsonify({"status": "success", "seigr_id": seigr_identity.senary_id})
            else:
                return jsonify({"error": "Failed to decrypt Seigr ID. Check your password."}), 403
        else:
            return jsonify({"error": "Seigr ID not found"}), 404
    except Exception as e:
        logger.error(f"Failed to retrieve Seigr ID: {e}")
        return jsonify({"error": "Failed to retrieve Seigr ID"}), 500
