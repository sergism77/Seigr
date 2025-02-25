import logging
import os
from src.execution.capsule_runtime import CapsuleExecutor
from config import Config
from dot_seigr.seed_dot_seigr import SeedDotSeigr
from src.dot_seigr.dot_seigr import DotSeigr
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    CreateSeedClusterResponse,
    EncodeDataResponse,
    OperationStatus,
)

logger = logging.getLogger("ClusterCapsule")

def create_seed_cluster():
    """Creates a root cluster using SeedDotSeigr and saves metadata."""
    try:
        initial_hash = "root_hash"
        seed = SeedDotSeigr(initial_hash)

        if not os.path.exists(Config.CLUSTER_DIRECTORY):
            os.makedirs(Config.CLUSTER_DIRECTORY)
        seed_path = seed.save_to_disk(Config.CLUSTER_DIRECTORY, filename="seed_cluster.protobuf")

        response = CreateSeedClusterResponse(status=OperationStatus.SUCCESS, path=seed_path)
        logger.info(f"Seed cluster created successfully at: {seed_path}")
        return response.SerializeToString()

    except Exception as e:
        logger.error(f"Failed to create seed cluster: {e}")
        response = CreateSeedClusterResponse(status=OperationStatus.FAILURE, path="")
        return response.SerializeToString()

def encode_data(data):
    """Encodes data and stores it as .seigr files in clusters."""
    try:
        creator_id = "user_creator_id"
        base_dir = Config.CLUSTER_DIRECTORY

        dot_seigr = DotSeigr(data, creator_id, base_dir, original_filename="uploaded_data")
        seed = SeedDotSeigr("root_hash")
        updated_seed_path = dot_seigr.create_segmented_seigr_files(base_dir, seed)

        response = EncodeDataResponse(status=OperationStatus.SUCCESS, seed_path=updated_seed_path)
        logger.info(f"Data encoded and stored at: {updated_seed_path}")
        return response.SerializeToString()

    except Exception as e:
        logger.error(f"Failed to encode data: {e}")
        response = EncodeDataResponse(status=OperationStatus.FAILURE, seed_path="")
        return response.SerializeToString()

# Register Capsule Execution Tasks
CapsuleExecutor.register_task("create_seed_cluster", create_seed_cluster)
CapsuleExecutor.register_task("encode_data", encode_data)
