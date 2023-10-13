from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from models import db, User
from werkzeug.security import generate_password_hash  
import secrets
from datetime import datetime, timedelta
from flask_mail import Message
from mail import mail  # Import mail from the mail.py module
from flask import url_for, session
import re  # Import the re module for regular expressions
from werkzeug.security import check_password_hash
# Generate public and private keys for a user (you would typically do this during user registration)
def generate_key_pair():
    key = RSA.generate(2048)  # Adjust key size as needed
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt a message using the recipient's public key
def encrypt_message(message, recipient_public_key):
    recipient_key = RSA.import_key(recipient_public_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Decrypt a message using the recipient's private key
def decrypt_message(encrypted_message, recipient_private_key):
    recipient_key = RSA.import_key(recipient_private_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message


# utils.py

def loginUser( username, password):
    error_messages = []
    # check if username exist
    if not username:
        error_messages.append({"message": "Username is required", "type": "username"})

    # check if password exist
    if not password:
        error_messages.append({"message": "Password is required", "type": "password"})
    
    

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        # Successfully authenticated
        session['user_id'] = user.id
        session['is_logged_in'] = True
        return "Successfully login", 200
    else:
        if username and password:
            # error message append the invalid email pass
            error_messages.append({"message": "Invalid email or password", "type": "invalid"})
    if error_messages:
        return error_messages, 400

def registerUser(email, username, password, confirm_password):
    # Initialize an empty list to store error messages
    error_messages = []

    # Define a regular expression pattern for password validation
    # This pattern requires at least one uppercase letter, one lowercase letter, and one digit (number).
    password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$')

    # Validate the password
    if password:
        if not password_pattern.match(password):
            error_messages.append({"message": "Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "password"})
    else:
         error_messages.append({"message": "Password is required", "type": "password"})
         
    if confirm_password: 
        if not password_pattern.match(confirm_password):
            error_messages.append({"message": "Confirm Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "confirm-password"})
    else:
        error_messages.append({"message": "Confirm password is required", "type": "confirm-password"})

    if email:
    # Validate the email format using a regular expression
        email_pattern = re.compile(r'^\S+@\S+\.\S+$')
        if not email_pattern.match(email):
            error_messages.append({"message": "Invalid email format", "type": "email"})
        else:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                error_messages.append({"message": "Email already exists", "type": "email"})
    else: 
        error_messages.append({"message": "Email is required", "type": "email"})

    if username:
        # Validate the username format (no spaces, only underscores allowed)
        username_pattern = re.compile(r'^[^\s]+(?:_[^\s]+)*$')
        if not username_pattern.match(username):
            error_messages.append({"message": "Special characters and spaces are not allowed", "type": "username"})
        else:
            existing_username = User.query.filter_by(username=username).first()
            if existing_username:
                error_messages.append({"message": "Username already exists", "type": "username"})
    else:
        error_messages.append({"message": "Username is required", "type": "username"})
        
    # Check if error_messages array doesn't contain "password" or "confirm-password" types
    has_password_or_confirm_password_error = any(error.get("type") in ["password", "confirm-password"] for error in error_messages)

    if not has_password_or_confirm_password_error:
        if password and confirm_password and password != confirm_password:
            error_messages.append({"message": "Passwords do not match", "type": "password-not-match"})
    
    if error_messages:
        return error_messages, 400

    private_key, public_key = generate_key_pair()
    hashed_password = generate_password_hash(password)

   # If no errors, proceed with user registration
    new_user = User(email=email, username=username, password=hashed_password, public_key= public_key, private_key=private_key )

    # Save the user to the database
    db.session.add(new_user)
    db.session.commit()
    
    # ... the rest of your registration code ...
  
    return "Account successfully created", 200


def sendResetPasswordEmail(email):
    # Check if email exists in the database
    if not email:
        return 'Email is required', 400
    
    user = User.query.filter_by(email=email).first()

    if user:
        # Generate a secure token
        token = secrets.token_hex(16)

        # Save the token and its expiration time in the database
        user.token = token
        user.token_expiration = datetime.now() + timedelta(minutes=30)
        db.session.commit()

        # Send the reset email
        msg = Message('Password Reset Request', sender='securechat@gmail.com', recipients=[email])
        msg.body = f"Please click the following link to reset your password: {url_for('chat_app_api.resetPasswordConfirm', token=token, _external=True)}"
        mail.send(msg)
        return 'An email with instructions to reset your password has been sent.', 200
    else:
        print("HERE")
        return 'Email does not exist', 400

# Make the reset password here
def resetPassword(token, new_password, confirm_password):
    error_messages = []
    password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$')
    # Check if password exist then append the error message
    # Validate the password
    if new_password:
        if not password_pattern.match(new_password):
            error_messages.append({"message": "New Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "new-password"})
    else:
         error_messages.append({"message": "New Password is required", "type": "new-password"})
         
    if confirm_password: 
        if not password_pattern.match(confirm_password):
            error_messages.append({"message": "Confirm Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "confirm-password"})
    else:
        error_messages.append({"message": "Confirm password is required", "type": "confirm-password"})

    # Check if error_messages array doesn't contain "password" or "confirm-password" types
    has_password_or_confirm_password_error = any(error.get("type") in ["new-password", "confirm-password"] for error in error_messages)

    if not has_password_or_confirm_password_error:
        if new_password and confirm_password and new_password != confirm_password:
            error_messages.append({"message": "Passwords do not match", "type": "password-not-match"})

    if error_messages:
        return error_messages, 400
    else:
        # query a user that match the token
        user = User.query.filter_by(token=token).first()
        
        # if statement for user and check the token expiration is greater that now
        if user and user.token_expiration > datetime.now():
            # update the password and token
            hashed_password = generate_password_hash(new_password)
            user.password = hashed_password
            user.token = None
            user.token_expiration = None
            db.session.commit()
            return 'Password successfully reset', 200
        else:
            return 'Invalid or expired token', 400
    