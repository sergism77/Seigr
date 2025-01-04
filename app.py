# app.py
import os
import sys

from flask import Flask

from config import Config
from routes import cluster_routes, identity_routes, monitor_routes, ping_routes

# Ensure `src` is added to the system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Register blueprints from each modular route
app.register_blueprint(identity_routes.bp)
app.register_blueprint(ping_routes.bp)
app.register_blueprint(cluster_routes.bp)
app.register_blueprint(monitor_routes.bp)

if __name__ == "__main__":
    app.run(debug=True)
