# routes/cluster_routes.py
from flask import Blueprint, jsonify, request
from src.dot_seigr.dot_seigr import DotSeigr
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr
from config import Config
import os

bp = Blueprint('cluster_routes', __name__)

@bp.route('/create_seed_cluster', methods=['POST'])
def create_seed_cluster():
    """Creates a root cluster using SeedDotSeigr and saves metadata."""
    initial_hash = "root_hash"  # Placeholder root hash
    seed = SeedDotSeigr(initial_hash)
    seed_path = seed.save_to_disk(Config.CLUSTER_DIRECTORY)
    return jsonify({"status": "seed_cluster_created", "path": seed_path})

@bp.route('/encode_data', methods=['POST'])
def encode_data():
    """Encodes data and stores it as .seigr files in clusters."""
    data = request.data  # Assumes binary data sent via POST
    creator_id = "user_creator_id"  # Placeholder creator ID
    base_dir = Config.CLUSTER_DIRECTORY
    dot_seigr = DotSeigr(data, creator_id, base_dir, original_filename="uploaded_data")

    # Process segmentation and encoding
    seed = SeedDotSeigr("root_hash")
    updated_seed = dot_seigr.create_segmented_seigr_files(base_dir, seed)
    return jsonify({"status": "data_encoded", "seed_path": updated_seed})
