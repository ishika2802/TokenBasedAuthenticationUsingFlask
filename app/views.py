import os
from flask import Blueprint, request, current_app, jsonify
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt, decode_token, get_jwt_identity
from bson import ObjectId  # Import to handle ObjectId conversion


# Configure Flask to use 'dist' for static files
views = Blueprint('views', __name__)
UPLOAD_FOLDER = 'static/assets/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


def allowed_file_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route("/dashboard", methods=['GET'])
@jwt_required()
def homePage():
    current_user = get_jwt_identity()  # Get the user from JWT
    print(f"current user identity : {current_user}")
    return jsonify({"message": "Navigation to dashboard success"})


@views.route('/getUser', methods=['GET'])
@jwt_required()
def getUser():
    
    userCollection = current_app.db['users']
    profileCollection = current_app.db["profiles"]
    user_id = get_jwt_identity()
    print(user_id)
    try:
        user_object_id = ObjectId(user_id)
    except:
        return jsonify({"message": "Invalid user ID format in JWT"}), 400

    profileDetails = profileCollection.find_one({"_id": user_object_id})

    if not profileDetails:
        return jsonify({"message": "Profile not found"}), 404  

    # Convert ObjectId to string before returning JSON
    if "_id" in profileDetails:
        profileDetails["_id"] = str(profileDetails["_id"])

    return jsonify({"user": profileDetails}), 200

@views.route('/updateUser', methods=['PUT'])
@jwt_required()
def updateUser():
    userCollection = current_app.db['users']
    profileCollection = current_app.db["profiles"]
    user_id = get_jwt_identity()

    try:
        user_object_id = ObjectId(user_id)
    except:
        return jsonify({"message": "Invalid user ID format in JWT"}), 400

    # Fetch user details
    # userProfileDetails = userCollection.find_one({"_id": user_object_id}, {"_id": 0, "email": 1, "userName": 1})
    userProfileDetails = userCollection.find_one({"_id": user_object_id})
    if not userProfileDetails:
        return jsonify({"message": "User not found in users collection"}), 404  

    current_email = userProfileDetails["email"] 
    # profileDetails = profileCollection.find_one({"email": current_email}, {"_id": 0})
    profileDetails = profileCollection.find_one({"_id": user_object_id})

    data = request.form
    update_data = {}

    allowed_fields = ["email", "countryCode", "mobileNumber", "address", "address2", "country", "state", "city", "zipCode"]
    update_data.update({field: data[field] for field in allowed_fields if field in data and data[field]})

    new_email = data.get("email")
    if new_email and new_email != current_email:
        # Check if email is already taken
        existing_user = userCollection.find_one({"email": new_email})
        if existing_user:
            return jsonify({"message": "Email already in use. Choose a different one."}), 400
        
        update_data["email"] = new_email

    if "image" in request.files:
        file = request.files["image"]
        if file and allowed_file_extension(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join("uploads", filename)
            os.makedirs("uploads", exist_ok=True)
            file.save(file_path)
            update_data["image"] = filename
        else:
            return jsonify({"message": "Invalid image format. Allowed formats: png, jpg, jpeg, gif."}), 400

    print("Updating profile with:", update_data)

    if not update_data:
        return jsonify({"message": "No valid data to update.", "status": "error"}), 400

    profileResult = profileCollection.update_one({"email": current_email}, {"$set": update_data})

    if new_email and new_email != current_email:
        userResult = userCollection.update_one({"_id": user_object_id}, {"$set": {"email": new_email}})
        if userResult.modified_count == 0:
            return jsonify({"message": "Failed to update user email."}), 500

    if profileResult.modified_count > 0:
        return jsonify({"message": "Profile updated successfully."}), 200
    else:
        return jsonify({"message": "No changes detected."}), 200


@views.route("/userProfileSetting", methods=['GET'])
@jwt_required()
def userSettings():
    current_user = get_jwt_identity()  # Get the user from JWT
    print(f"current user identity : {current_user}")
    return jsonify({"message": "Navigation to user profile success"})




