from flask import Flask, request, current_app, jsonify
import os
from os import path
from flask_pymongo import PyMongo
from pymongo import MongoClient 
from flask_mail import Mail
import jwt
from functools import wraps
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__, static_url_path='/static', static_folder=os.path.join(os.getcwd(), 'static/assets'), template_folder=os.path.join(os.getcwd(), 'templates'))

    BLOCKLIST = set()

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
    jwt = JWTManager(app)
    
    # Initialize MongoDB client
    mongo_uri = "mongodb://localhost:27017" 
    client = MongoClient(mongo_uri)
    app.mongo_client = client
    app.db = client['cms']


    # Test MongoDB connection
    try:
        client.admin.command('ping')
        print("Connected to MongoDB!")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        raise e
    
    # Configure the app with settings for Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587  # TLS port
    app.config['MAIL_USE_TLS'] = True  # Use TLS instead of SSL
    app.config['MAIL_USE_SSL'] = False  # Set SSL to False
    app.config['MAIL_USERNAME'] = "abc@mail.com"
    app.config['MAIL_PASSWORD'] = "16 character password"
    app.config['MAIL_DEFAULT_SENDER'] = "abc@mail.com"
    
    mail = Mail(app)
    mail.init_app(app)

    
    # Import blueprints
    from app.views import views
    from app.auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    # Token Required Decorator
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')

            if not token:
                return jsonify({'message': 'Token is missing!'}), 401

            try:
                token = token.split("Bearer ")[-1]  # Extract token
                data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = data['user_id']  # Retrieve user from DB if needed
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 401

            return f(current_user, *args, **kwargs)
        return decorated

    # Correct function definition
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in BLOCKLIST  # Ensure BLOCKLIST is a set or dictionary

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description": "The token has been revoked.", "error": "token_revoked"}
            ),
            401,
        )
    
    return app  