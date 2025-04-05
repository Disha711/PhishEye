import pandas as pd
import xgboost as xgb
import numpy as np
from flask import Flask, request, jsonify
import os
import time
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from pymongo import MongoClient
from auth import auth_bp
from dotenv import load_dotenv
from feature_extraction import extract_features
import certifi
from flask_cors import CORS

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["phishi_eye"]
reports_collection = db["reports"]
urls_collection = db["phishing_urls1"]

# JWT Setup
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your_secret_key")
jwt = JWTManager(app)

# Register auth blueprint
app.register_blueprint(auth_bp)

# Load model globally (Optimized)
booster = None
def load_model():
    global booster
    if booster is None:
        booster = xgb.Booster()
        booster.load_model("xgboost_model.json")
    return booster

# Features expected
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

# Save report helper
def save_to_reports(user, url, prediction, confidence):
    reports_collection.insert_one({
        "user": user,
        "url": url,
        "prediction": prediction,
        "confidence": confidence,
        "timestamp": int(time.time())  # Store timestamp as integer
    })

@app.route("/", methods=["GET"])
def home():
    return "Phishing Detection API is running!", 200

# Predict endpoint
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if "url" not in data:
            return jsonify({"error": "Missing 'url' field in request"}), 400

        url = data["url"]

        # Check if URL already exists
        existing_entry = urls_collection.find_one({"url": url})
        if existing_entry:
            return jsonify({
                "url": url,
                "prediction": existing_entry["prediction"],
                "confidence": existing_entry.get("confidence"),
                "message": "Fetched from database"
            })

        # Extract features
        features = extract_features(url)
        if features is None:
            return jsonify({"error": "Feature extraction failed"}), 500

        df_input = pd.DataFrame([features], columns=FEATURE_NAMES)
        booster = load_model()
        dmatrix = xgb.DMatrix(df_input, feature_names=FEATURE_NAMES)
        prediction = booster.predict(dmatrix)

        probability = float(prediction[0])
        result = "Phishing" if probability > 0.5 else "Legitimate"

        # Save globally in URL collection
        urls_collection.insert_one({
            "url": url,
            "prediction": result,
            "confidence": round(probability, 4),
            "timestamp": int(time.time())
        })

        return jsonify({
            "url": url,
            "prediction": result,
            "confidence": round(probability, 4)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Save report for user (called after /predict from frontend)
@app.route("/report", methods=["POST"])
@jwt_required()
def save_report():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()

        url = data.get("url")
        prediction = data.get("prediction")
        confidence = data.get("confidence", 0.5)

        if not url or not prediction:
            return jsonify({"error": "Missing required fields"}), 400

        save_to_reports(
            user=current_user,
            url=url,
            prediction=prediction,
            confidence=confidence
        )

        return jsonify({"message": "Report saved"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get latest report for logged-in user
@app.route("/report", methods=["GET"])
@jwt_required()
def get_latest_report():
    try:
        current_user = get_jwt_identity()

        latest_report = reports_collection.find_one(
            {"user": current_user},
            sort=[("timestamp", -1)]
        )

        if not latest_report:
            return jsonify({"error": "No report found for this user"}), 404

        return jsonify({
            "url": latest_report["url"],
            "prediction": latest_report["prediction"],
            "confidence": latest_report.get("confidence", 0.5)
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Clear user report history
@app.route("/report", methods=["DELETE"])
@jwt_required()
def delete_user_report():
    try:
        current_user = get_jwt_identity()
        reports_collection.delete_many({"user": current_user})
        return jsonify({"message": "Report(s) deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
