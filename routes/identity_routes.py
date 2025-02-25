# routes/identity_routes.py
import logging
import os


from config import Config
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import (
    CreateSeigrIdRequest,
    GenericResponse,
    GetSeigrIdRequest,
)
from src.identity.seigr_identity import SeigrIdentity

bp = Blueprint("identity_routes", __name__)
logger = logging.getLogger(__name__)


@bp.route("/create_seigr_id", methods=["POST"])
def create_seigr_id():
    """Generates a new Seigr ID and saves it securely in the user's local .seigr directory."""
    try:
        # Deserialize incoming protobuf request data
        data = CreateSeigrIdRequest()
        data.ParseFromString(request.get_data())
        password = data.password

        if not password:
            error_response = GenericResponse(
                status=GenericResponse.FAILURE,
                message="Password is required to create Seigr ID",
                error_code=400,
            )
            return Response(
                error_response.SerializeToString(),
                content_type="application/octet-stream",
            )

        seigr_identity = SeigrIdentity()
        seigr_id = seigr_identity.generate_seigr_id()
        seigr_identity.set_encryption_key(password=password)

        # Define the path to save the Seigr ID
        if not os.path.exists(Config.SEIGR_ID_DIRECTORY):
            os.makedirs(Config.SEIGR_ID_DIRECTORY)
        seigr_id_path = os.path.join(Config.SEIGR_ID_DIRECTORY, "seigr_id.protobuf")

        seigr_identity.save_to_external(seigr_id_path)

        # Prepare and serialize the success response
        success_response = GenericResponse(
            status=GenericResponse.SUCCESS,
            message="Seigr ID created successfully",
            path=seigr_id_path,
        )
        logger.info("Seigr ID created and saved successfully.")
        return Response(
            success_response.SerializeToString(),
            content_type="application/octet-stream",
        )
    except Exception as e:
        error_response = GenericResponse(
            status=GenericResponse.FAILURE,
            message="Failed to create Seigr ID",
            error_code=500,
        )
        logger.error(f"Failed to create Seigr ID: {e}")
        return Response(error_response.SerializeToString(), content_type="application/octet-stream")


@bp.route("/get_seigr_id", methods=["POST"])
def get_seigr_id():
    """Retrieves and decrypts the Seigr ID from the local storage if available."""
    try:
        # Deserialize incoming protobuf request data
        data = GetSeigrIdRequest()
        data.ParseFromString(request.get_data())
        password = data.password

        if not password:
            error_response = GenericResponse(
                status=GenericResponse.FAILURE,
                message="Password is required to retrieve Seigr ID",
                error_code=400,
            )
            return Response(
                error_response.SerializeToString(),
                content_type="application/octet-stream",
            )

        seigr_identity = SeigrIdentity()
        seigr_id_path = os.path.join(Config.SEIGR_ID_DIRECTORY, "seigr_id.protobuf")

        if os.path.exists(seigr_id_path):
            if seigr_identity.load_from_external(seigr_id_path, password=password):
                success_response = GenericResponse(
                    status=GenericResponse.SUCCESS,
                    message="Seigr ID retrieved successfully",
                    path=seigr_id_path,
                )
                return Response(
                    success_response.SerializeToString(),
                    content_type="application/octet-stream",
                )
            else:
                error_response = GenericResponse(
                    status=GenericResponse.FAILURE,
                    message="Failed to decrypt Seigr ID. Check your password.",
                    error_code=403,
                )
                return Response(
                    error_response.SerializeToString(),
                    content_type="application/octet-stream",
                )
        else:
            error_response = GenericResponse(
                status=GenericResponse.FAILURE,
                message="Seigr ID not found",
                error_code=404,
            )
            return Response(
                error_response.SerializeToString(),
                content_type="application/octet-stream",
            )
    except Exception as e:
        error_response = GenericResponse(
            status=GenericResponse.FAILURE,
            message="Failed to retrieve Seigr ID",
            error_code=500,
        )
        logger.error(f"Failed to retrieve Seigr ID: {e}")
        return Response(error_response.SerializeToString(), content_type="application/octet-stream")
