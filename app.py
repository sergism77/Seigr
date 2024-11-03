import sys
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
import uuid

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
            file_id = str(uuid.uuid4())
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{file_id}_{uploaded_file.filename}")
            uploaded_file.save(file_path)
            
            try:
                # Initialize encoder and perform encoding
                with open(file_path, "rb") as f:
                    data = f.read()
                encoder = SeigrEncoder(data, creator_id=file_id, base_dir=app.config["ENCODED_FOLDER"])
                encoder.encode()
                
                flash("File successfully encoded.", "success")
                return redirect(url_for("home"))
            except Exception as e:
                flash(f"Encoding failed: {e}", "error")
                return redirect(url_for("encode"))

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
                seed_file_paths.append(file_path)

            try:
                # Initialize decoder and perform decoding
                decoder = SeigrDecoder(seed_files=seed_file_paths, base_dir=app.config["ENCODED_FOLDER"])
                decoded_data = decoder.decode()

                # Save the decoded file
                decoded_file_path = os.path.join(app.config["DECODED_FOLDER"], "decoded_output.txt")
                with open(decoded_file_path, "wb") as f:
                    f.write(decoded_data)

                flash("File successfully decoded.", "success")
                return send_file(decoded_file_path, as_attachment=True)
            except Exception as e:
                flash(f"Decoding failed: {e}", "error")
                return redirect(url_for("decode"))

    return render_template("decode.html")

if __name__ == "__main__":
    app.run(debug=True)
