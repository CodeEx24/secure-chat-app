from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet

from models import db, User, Messages, ChattedUser
from werkzeug.security import generate_password_hash  
import secrets
from datetime import datetime, timedelta
from flask_mail import Message
from mail import mail  # Import mail from the mail.py module
from flask import url_for, session
import re  # Import the re module for regular expressions
from werkzeug.security import check_password_hash
import hashlib
import base64
# Generate public and private keys for a user (you would typically do this during user registration)
def generate_key_pair():
    key = RSA.generate(2048)  # Adjust key size as needed
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

# Function to encrypt a private key using Fernet
def encrypt_private_key(private_key, encryption_key):
    encrypted_private_key = encryption_key.encrypt(private_key)
    return encrypted_private_key

# Function to decrypt a private key using Fernet
def decrypt_private_key(encrypted_private_key, encryption_key):
    decrypted_private_key = encryption_key.decrypt(encrypted_private_key)
    return decrypted_private_key


# Function to generate a Fernet key from a string
def generate_fernet_key_from_string(s):
    # Choose a hashing algorithm (SHA-256 in this example)
    hash_algorithm = hashlib.sha256()
    # Update the hasher with the bytes of the string
    hash_algorithm.update(s.encode('utf-8'))
    # Get the digest (hash) and use it as the key material
    key = hash_algorithm.digest()
    # Trim or pad the key to 32 bytes
    key = key[:32] if len(key) >= 32 else key.ljust(32, b' ')

    # Encode the key in URL-safe base64 format
    encoded_key = base64.urlsafe_b64encode(key)
    return Fernet(encoded_key)

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
        session['user_name'] = user.username
        session['is_logged_in'] = True
        session['private_key']=user.private_key
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
        # Convert the PEM-encoded keys to strings
    private_key_str = private_key.decode('utf-8')
    public_key_str = public_key.decode('utf-8')
    
    # Example usage:
    string_to_hash = "your_secret_string"
    fernet_key = generate_fernet_key_from_string(string_to_hash)
    encrypted_private_key= encrypt_private_key(private_key, fernet_key)
    encrypted_private_key_str = encrypted_private_key.decode('utf-8')
    hashed_password = generate_password_hash(password)
    
    
    
    if(encrypt_private_key == private_key_str or encrypt_private_key == private_key):
        print("WE ARE THE SAME")
    else:
        print("FERNET KEY: ", fernet_key)
        print("encrypted_private_key: ", encrypted_private_key)
        print("encrypted_private_key_str: ", encrypted_private_key_str)
    
    # Decrypt the private key
    decrypted_key = decrypt_private_key(encrypted_private_key, fernet_key)

    print("DECRYPRYPTED KEY: ", decrypted_key.decode('utf-8'))  # Assuming the private key is a text, use the appropriate encoding
    
   # If no errors, proceed with user registration
    new_user = User(email=email, username=username, password=hashed_password, public_key= public_key_str, private_key=encrypted_private_key )

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
    
    
def getUsernameList(username, query_username):
    if query_username:
        # Filter the users, excluding the current user's username
        users_query = User.query.filter(
            User.username.ilike(f'%{query_username}%'),
            User.username != username
        ).limit(10)

        # Execute the query to fetch the results
        users = users_query.all()

        if users: 
            print("EXISTING USER: ")
            # For loop the users and return the user as an object 
            users_list = [{"id": user.id, "username": user.username} for user in users]
            return users_list, 200
        else:
            print("NO USER: ")
            return "No users found", 400
    else:
        print("PLEASE TYPE: ")
        # Return "Please type to search"
        return "Please type to search", 400


def retrieve_chat_history(sender_id, recipient_id):

    # The current user chatting with for example username 3
    userSendMessages = db.session.query(
                ChattedUser).filter(ChattedUser.sender_id == sender_id, ChattedUser.recipient_id == recipient_id).all()
    userRecieveMessages = db.session.query(
                ChattedUser).filter(ChattedUser.sender_id == recipient_id, ChattedUser.recipient_id == sender_id).all()
    
    if userSendMessages and userRecieveMessages:
        print("userSendMessages: ", userSendMessages)
        print("userRecieveMessages: ", userRecieveMessages)
    #     sendChatHistory = db.session.query(Messages).filter(Messages.chatted_id == userSendMessages.id)
    #     recieveChatHistory = db.session.query(Messages).filter(Messages.chatted_id == userRecieveMessages.id)
        
        
    # else:
    #     print("NO CHAT HISTORY WITH USER")