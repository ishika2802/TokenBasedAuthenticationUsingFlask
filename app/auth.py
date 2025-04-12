import os
from flask import Blueprint, request, redirect, url_for, flash, current_app, app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail
import jwt
from bson import ObjectId
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt, decode_token, get_jwt_identity


BLOCKLIST = set()

def generate_reset_token(email):
    user = current_app.db['users'].find_one({'email': email})
    # token = create_access_token(identity=str(user['_id']))
    token = create_access_token(identity=user["email"])

    return token

def send_reset_email(email):
    token = generate_reset_token(email)
    reset_url = f"{request.url_root}resetUserPassword/{token}"
    
    mail = current_app.extensions['mail']
    # Email content
    msg = Message("Password Reset Request",
                  sender="abc@mail.com",
                  recipients=[email])
    msg.body = f"""
    To reset your password, visit the following link:
    {reset_url}
    If you did not make this request, please ignore this email.
    """
    mail.send(msg)

auth = Blueprint('auth', __name__)

@auth.route("/login", methods=["GET", "POST"])
def loginUser():
        data = request.get_json()
        print("Received data:", data)
    
        if not data:
            return jsonify({"message": "Invalid request. Ensure JSON body is sent."}), 400

        email = data.get("email")
        password = data.get("password")

        print(f"Email: {email}, Password: {password}")  # Debugging
        user = current_app.db['users'].find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            access_token = create_access_token(identity=str(user['_id']))
            return jsonify({'message': 'Login successful!', 'token': access_token}), 200  # Return redirect URL
        
        return jsonify({'message': 'Invalid email or password'}), 401

@auth.route('/signup', methods=['GET','POST'])
def registerUser():
        # Get form data
        data = request.get_json()
        userName = data.get('userName')
        email = data.get('email')
        password = data.get('password')

        # Debugging output
        print(f"Received - Username: {userName}, Email: {email}, Password: {password}")

        # Existing logic
       
        # Input validation (Checking if any field is missing)
        if not userName or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('auth.registerUser'))

        userCollection = current_app.db['users']
        profileCollection = current_app.db['profiles']
        # existingUser = userCollection.find_one({'userName' : userName}, {"email" : email})
        existingUser = userCollection.find_one({'$or': [{'userName': userName}, {'email': email}]})

        if existingUser:
            return jsonify({'message': 'Username or Email already exists'}), 409
        
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            try:
                # Log form data for debugging
                print(f"Form data - UserName: {userName}, Email: {email}, Password: {password}")
                user_id = ObjectId()
                # Save the user to the database
                result = userCollection.insert_one({
                    '_id' : user_id,
                    'userName' : userName,
                    'email': email,
                    'password': hashed_password
                })

                profileInsert = profileCollection.insert_one({
                    '_id' : user_id,
                    'userName' : userName,
                    'email' : email,
                    'image' : "",
                    'countryCode' : "",
                    'mobileNumber' : "",
                    'address' : "",
                    'address2' : "",
                    'country' : "",
                    'state' : "",
                    "city" : "",
                    "zipCode" : ""
                })

                # print(f"Data inserted with ID: {result.inserted_id}")  # Log the inserted id for confirmation
                return jsonify({'message':'User registered success!'}), 200
            
            except Exception as e:
                print(f"Error inserting to MongoDB: {e}")  # Log the error to identify any issues
                return jsonify({'message':'Error registering user!. Please try again'}), 500


@auth.route('/resetUserPassword/<token>', methods=['POST'])
def reset_password(token):
    try:
        # Decode JWT token
        decoded = decode_token(token)
        email = decoded.get('sub')  # 'sub' should contain the email
        print(f"Decoded email: {email}")

        if not email:
            return jsonify({'message': 'Invalid token: Email missing'}), 400

    except Exception as e:
        print(f"Token decode error: {str(e)}")
        return jsonify({'message': 'Invalid or expired password reset link.'}), 500

    # Check if user exists
    userCollection = current_app.db['users']
    user = userCollection.find_one({'email': {'$regex': f'^{email}$', '$options': 'i'}})

    if not user:
        print(f"User not found in DB: {email}")
        return jsonify({'message': 'User not found!'}), 404

    # Handle password reset form submission
    data = request.get_json()
    new_password = data.get('password')
    confirm_password = data.get('confirmPassword')

    if not new_password or not confirm_password:
        return jsonify({'message': 'Password field is empty!'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

    # Hash and update the password
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    result = userCollection.update_one({'email': {'$regex': f'^{email}$', '$options': 'i'}}, {'$set': {'password': hashed_password}})

    if result.matched_count == 0:
        return jsonify({'message': 'User not found!'}), 404

    print("Password change success")
    return jsonify({'message': 'Password changed successfully!'}), 200

@auth.route("/resetPassword", methods=['GET', 'POST'])
def resetUserPassword():
        data = request.get_json()
        email = data.get('email')

        # Debugging output
        print(f"Received - Email: {email}")
        if not email:
            print("email not entered")
            return jsonify({'message' : 'Email field is empty!.'}), 500
        
        userCollection = current_app.db['users']
        existingEmail = userCollection.find_one({'email': email})
        if existingEmail:
                # Send the reset email directly
                send_reset_email(email)
                print("message send success")
                return jsonify({'message' : 'Password reset link sent success!.'}), 200
        else:
            return jsonify({'message' : 'User not registered!.'}), 400

@auth.route("/logout", methods=["POST"])
@jwt_required()  # Requires a valid token for logout
def logout():
    jti = get_jwt()["jti"]  # Get the token's unique ID (jti)
    BLOCKLIST.add(jti)  # Blacklist it
    return jsonify({"message": "Successfully logged out!"}), 200

@auth.route('/changePassword', methods=['POST'])
@jwt_required()
def changePasswordPage():
    user_id = get_jwt_identity()
    print(f"JWT Identity: {user_id}")  # Debugging line

    # Convert user_id to ObjectId
    try:
        userCollection = current_app.db['users']
        user = userCollection.find_one({'_id': ObjectId(user_id)})
    except Exception as e:
        print(f"Invalid ObjectId: {user_id}")  # Debugging line
        return jsonify({'message': 'Invalid user ID!'}), 400

    if not user:
        print(f"User not found in DB: {user_id}")  # Debugging line
        return jsonify({'message': 'User not found!'}), 404

    data = request.get_json()
    current_password = data.get("password")
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if not current_password or not new_password or not confirm_password:
        return jsonify({'message': 'Missing fields!'}), 400

    # Verify current password
    if not check_password_hash(user.get('password', ''), current_password):
        return jsonify({'message': 'Incorrect current password!'}), 400

    if new_password !=  confirm_password:
         return jsonify({'message': 'passwords donot match!'}), 400

    # Hash new password and update in DB
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    userCollection.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_password}})

    return jsonify({'message': 'Password changed successfully!'}), 200

@auth.route('/deleteAccount/<user_id>', methods=['DELETE'])
@jwt_required()
def deleteAccount(user_id):
    userCollection = current_app.db["users"]
    profileCollection = current_app.db["profiles"]
    try:
        result = userCollection.delete_one({"_id": ObjectId(user_id)})
        profileResult = profileCollection.delete_one({"id": ObjectId(user_id)})
        
        if result.deleted_count == 1:
            return jsonify({"message": "Account deleted successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500