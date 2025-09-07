from flask import Flask
from flask_pymongo import PyMongo
from routes.auth import auth_bp
from routes.chat import chat_bp
from routes.files import files_bp
from routes.search import search_bp
import os

app = Flask(__name__)

app.config["MONGO_URI"] = f"mongodb://{os.getenv('DB_HOST', 'db')}:{os.getenv('DB_PORT', '27017')}/{os.getenv('DB_NAME', 'dbname')}"
app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "marika-is-playing-with-luna")
app.config['MAX_CONTENT_LENGTH'] = 0.5 * 1024 * 1024

mongo = PyMongo(app)
app.mongo = mongo

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(chat_bp, url_prefix="/chat")
app.register_blueprint(files_bp, url_prefix="/files")
app.register_blueprint(search_bp, url_prefix="/search")

@app.route("/")
def index():
    return {"status": "Service is running"}
