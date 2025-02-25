# routes/cluster_routes.py
import logging
import os


from config import Config
from dot_seigr.seed_dot_seigr import SeedDotSeigr
from src.dot_seigr.dot_seigr import DotSeigr
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    CreateSeedClusterResponse,
    EncodeDataResponse,
    OperationStatus,
)

bp = Blueprint("cluster_routes", __name__)
logger = logging.getLogger(__name__)


@bp.route("/create_seed_cluster", methods=["POST"])
def create_seed_cluster():
    """Creates a root cluster using SeedDotSeigr and saves metadata."""
    try:
        initial_hash = "root_hash"  # Placeholder root hash for seed initialization
        seed = SeedDotSeigr(initial_hash)

        # Define path for saving the cluster seed as a .protobuf file
        if not os.path.exists(Config.CLUSTER_DIRECTORY):
            os.makedirs(Config.CLUSTER_DIRECTORY)
        seed_path = seed.save_to_disk(Config.CLUSTER_DIRECTORY, filename="seed_cluster.protobuf")

        # Construct and serialize a success response
        response = CreateSeedClusterResponse(status=OperationStatus.SUCCESS, path=seed_path)
        logger.info(f"Seed cluster created successfully at path: {seed_path}")
        return Response(response.SerializeToString(), content_type="application/octet-stream")

    except Exception as e:
        logger.error(f"Failed to create seed cluster: {e}")
        # Construct and serialize an error response
        response = CreateSeedClusterResponse(
            status=OperationStatus.FAILURE,
            path="",
        )
        return Response(
            response.SerializeToString(),
            content_type="application/octet-stream",
            status=500,
        )


@bp.route("/encode_data", methods=["POST"])
def encode_data():
    """Encodes data and stores it as .seigr files in clusters."""
    try:
        data = request.data  # Binary data received via POST
        creator_id = "user_creator_id"  # Placeholder for the actual creator ID
        base_dir = Config.CLUSTER_DIRECTORY

        # Initialize DotSeigr with data and creator details
        dot_seigr = DotSeigr(data, creator_id, base_dir, original_filename="uploaded_data")

        # Perform segmentation and encoding
        seed = SeedDotSeigr("root_hash")
        updated_seed_path = dot_seigr.create_segmented_seigr_files(base_dir, seed)

        # Construct and serialize a success response
        response = EncodeDataResponse(status=OperationStatus.SUCCESS, seed_path=updated_seed_path)
        logger.info(f"Data encoded and stored at path: {updated_seed_path}")
        return Response(response.SerializeToString(), content_type="application/octet-stream")

    except Exception as e:
        logger.error(f"Failed to encode data: {e}")
        # Construct and serialize an error response
        response = EncodeDataResponse(status=OperationStatus.FAILURE, seed_path="")
        return Response(
            response.SerializeToString(),
            content_type="application/octet-stream",
            status=500,
        )
