import sys
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import uuid
import logging

# Set up centralized logging to a file
LOG_FILE_PATH = os.path.join("logs", "dot_seigr.log")
os.makedirs("logs", exist_ok=True)  # Ensure the logs directory exists

logging.basicConfig(
    filename=LOG_FILE_PATH,
    level=logging.DEBUG,  # Set to DEBUG to capture all levels of log messages
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filemode="a"  # Append to log file
)

# Optionally set up logging to console for critical issues
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)  # Only show critical errors in console
formatter = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

# Set up logger
logger = logging.getLogger(__name__)

# Ensure the src directory is in the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dot_seigr.seigr_encoder import SeigrEncoder
from dot_seigr.seigr_decoder import SeigrDecoder

app = Flask(
    __name__,
    template_folder="src/templates",
    static_folder="src/static"
)
app.secret_key = "supersecretkey"

# Configurations for uploads and file storage
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ENCODED_FOLDER"] = "encoded_files"
app.config["DECODED_FOLDER"] = "decoded_files"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCODED_FOLDER"], exist_ok=True)
os.makedirs(app.config["DECODED_FOLDER"], exist_ok=True)

# Home route
@app.route("/")
def home():
    return render_template("home.html")

# Encoding route
@app.route("/encode", methods=["GET", "POST"])
def encode():
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file:
            logger.info("File upload detected. Starting encoding process.")
            file_id = str(uuid.uuid4())
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{str(file_id)}_{uploaded_file.filename}")
            uploaded_file.save(file_path)

            try:
                # Read and encode the file
                with open(file_path, "rb") as f:
                    data = f.read()
                encoder = SeigrEncoder(
                    data=data,
                    creator_id=file_id,
                    base_dir=app.config["ENCODED_FOLDER"],
                    original_filename=uploaded_file.filename
                )
                encoder.encode()
                flash("File successfully encoded.", "success")
                logger.info("Encoding process completed successfully.")
            except Exception as e:
                flash(f"Encoding failed: {e}", "error")
                logger.error(f"Encoding process failed: {e}")
            return redirect(url_for("home"))
        else:
            flash("No file detected for encoding.", "error")
            logger.error("No file detected for encoding.")
            return redirect(url_for("encode"))

    # If request is GET, render the encode template
    return render_template("encode.html")

# Decoding route
@app.route("/decode", methods=["GET", "POST"])
def decode():
    if request.method == "POST":
        seed_files = request.files.getlist("seed_files")
        if seed_files:
            seed_file_paths = []
            for file in seed_files:
                file_path = os.path.join(app.config["ENCODED_FOLDER"], file.filename)
                file.save(file_path)
                seed_file_paths.append(file.filename)  # Pass filenames, not paths

            try:
                # Initialize decoder and perform decoding
                decoder = SeigrDecoder(
                    cluster_files=seed_file_paths,
                    base_dir=app.config["ENCODED_FOLDER"]
                )
                decoded_file_path = decoder.decode()

                if decoded_file_path:
                    flash("File successfully decoded.", "success")
                    return send_file(decoded_file_path, as_attachment=True)
                else:
                    flash("Decoding failed: no data was decoded.", "error")
                    return redirect(url_for("decode"))

            except Exception as e:
                flash(f"Decoding failed: {e}", "error")
                logger.error(f"Decoding process failed: {e}")
                return redirect(url_for("decode"))

    return render_template("decode.html")

if __name__ == "__main__":
    app.run(debug=True)
