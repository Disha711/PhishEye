from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from pymongo import MongoClient
from functools import wraps

# MongoDB Connection
MONGO_URI = "mongodb+srv://phishuser:securepassword@phisheye.gf9n5.mongodb.net/phishi_eye?retryWrites=true&w=majority&appName=Phisheye"
client = MongoClient(MONGO_URI)
db = client["phishi_eye"]
users_collection = db["users"]

# JWT Secret Key
SECRET_KEY = "your_secret_key"  # You may want to keep this in an environment variable

auth_bp = Blueprint("auth", __name__)

# Token Required Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        # Check for the 'Bearer' prefix in the token
        if not token.startswith("Bearer "):
            return jsonify({"error": "Invalid token format!"}), 401

        token = token.split(" ")[1]  # Extract the actual token

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users_collection.find_one({"email": data["email"]})
            if not current_user:
                return jsonify({"error": "Invalid token!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.DecodeError:
            return jsonify({"error": "Failed to decode token!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Register User
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"email": email, "password": hashed_password})

    return jsonify({"message": "User registered successfully"}), 201

# Login User
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate JWT Token
    token = jwt.encode(
        {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({"message": "Login successful", "token": token}), 200

# Protected Route (For Testing Authentication)
@auth_bp.route("/protected", methods=["GET"])
@token_required
def protected_route(current_user):
    return jsonify({"message": "This is a protected route!", "user": current_user["email"]}), 200
