from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet

from models import db, User, Messages, ChattedUser, UserKey, SecurityQuestion
from werkzeug.security import generate_password_hash  
import secrets
from datetime import datetime, timedelta
from flask_mail import Message
from mail import mail  # Import mail from the mail.py module
from flask import url_for, session, jsonify
import re  # Import the re module for regular expressions
from werkzeug.security import check_password_hash
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from sqlalchemy import or_

# Generate public and private keys for a user (you would typically do this during user registration)
def generate_key_pair():
    key = RSA.generate(2048)  # Adjust key size as needed
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

# # Function to encrypt a private key using Fernet
# def encrypt_private_key(private_key, encryption_key):
#     encrypted_private_key = encryption_key.encrypt(private_key)
#     return encrypted_private_key

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


def generate_encryption_key(hashed_answer):
    # ... your existing code ...
    CONSTANT_SALT = b'\x8a\xff\xd1\xe2\x9c\xc8\xe3\x0e\x5d\x70\x4f\xab\x3d\xb9\x0a\x67'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=CONSTANT_SALT,
        length=32  # Ensure that the length is 32
    )
    encryption_key = kdf.derive(hashed_answer)


    return encryption_key


def encrypt_private_key(private_key, encryption_key):
    f = Fernet(base64.urlsafe_b64encode(encryption_key))
    encrypted_private_key = f.encrypt(private_key.encode())
    return encrypted_private_key

def decrypt_data(encrypted_data, encryption_key):
    try:
        f = Fernet(base64.urlsafe_b64encode(encryption_key))
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')  # Assuming the original data was a UTF-8 encoded string
    except Exception as e:
        # Handle decryption errors, e.g., incorrect key or data format
        return None  # Return None or raise an exception based on your error handling strategy

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
    
    if not user:
        error_messages.append({"message": "Invalid email or password", "type": "invalid"})
    
    elif user and check_password_hash(user.password, password):

        user_key = UserKey.query.filter_by(user_id=user.id).first()
        user_sq = SecurityQuestion.query.filter_by(user_id=user.id).first()

        
        hashed_answer = user_sq.answer.encode('utf-8')
    
        encryption_key = generate_encryption_key(hashed_answer)
        decrypt_private_key = decrypt_data(user_key.private_key, encryption_key)
        # Successfully authenticated
        session['user_id'] = user.id
        session['user_name'] = user.username
        session['is_logged_in'] = True
        session['private_key']=decrypt_private_key
        session['public_key']=user.public_key
        return "Successfully login", 200
    else:
        if username and password:
            # error message append the invalid email pass
            error_messages.append({"message": "Invalid email or password", "type": "invalid"})
    if error_messages:
        return error_messages, 400

def registerUser(email, fullname, username, password, confirm_password,  answer, question=None):
    
    # Initialize an empty list to store error messages
    error_messages = []

    # Check if question has a value if not throw an error with type of question
    if not question:
        error_messages.append({"message": "Security Question is required", "type": "question"})
        
    if not answer:
        error_messages.append({"message": "Answer is required", "type": "answer"})
        
    
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

    if fullname:
        # Validate the username format (no spaces, only underscores allowed)
        fullname_pattern = re.compile(r'^[a-zA-Z\s]+$')
        if not fullname_pattern.match(fullname):
            error_messages.append({"message": "Special characters are not allowed", "type": "fullname"})

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
    

    
    # encrypted_private_key= encrypt_private_key(private_key)
    hashed_password = generate_password_hash(password)
    
    hashed_answer = answer.encode('utf-8')

    
    # Generate encryption keys based on the user's hashed password
    encryption_key = generate_encryption_key(hashed_answer)
   
    # Encrypt the private key
    encrypted_private_key = encrypt_private_key(private_key_str, encryption_key)

   # If no errors, proceed with user registration
    new_user = User(email=email, name=fullname, username=username, password=hashed_password, public_key= public_key_str, key=encryption_key )

    # Save the user to the database
    db.session.add(new_user)
    db.session.commit()
    
        # Store the encrypted private key and the user ID in the database
    new_security_question = SecurityQuestion(user_id=new_user.id, question_id=question, answer=hashed_answer.decode('utf-8'))
    new_user_key = UserKey(private_key=encrypted_private_key.decode('utf-8'), user_id=new_user.id)

    # Save the user key to the database
    db.session.add(new_user_key)
    db.session.add(new_security_question)
    db.session.commit()
    
    # Decrypt the private key
    # Decrypt the private key
    # private_key_decrypted = decrypt_data(encrypted_private_key, encryption_key)

    
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
            # For loop the users and return the user as an object 
            users_list = [{"id": user.id, "username": user.username} for user in users]
            return users_list, 200
        else:
            return "No users found", 400
    else:
        # Return "Please type to search"
        return "Please type to search", 400


from sqlalchemy import or_

def retrieve_chat_history(sender_id, recipient_id, rendered_message=0, reverse=False):
    userSendMessages = db.session.query(
        ChattedUser).filter(ChattedUser.sender_id == sender_id, ChattedUser.recipient_id == recipient_id).first()
    userReceiveMessages = db.session.query(
        ChattedUser).filter(ChattedUser.sender_id == recipient_id, ChattedUser.recipient_id == sender_id).first()

    if userSendMessages or userReceiveMessages:
        query = db.session.query(Messages)
        
        if userSendMessages and not userReceiveMessages:
            query = query.filter(Messages.chatted_id == userSendMessages.id)
        elif userReceiveMessages and not userSendMessages:
            query = query.filter(Messages.chatted_id == userReceiveMessages.id)
        elif userSendMessages and userReceiveMessages:
            query = query.filter(
                or_(
                    Messages.chatted_id == userSendMessages.id,
                    Messages.chatted_id == userReceiveMessages.id
                )
            )
        
        sendChatHistory = query.order_by(Messages.timestamp.desc()).limit(50).offset(rendered_message)
        
        rendered_message_count = sendChatHistory.count()
        total_message_count = query.count()
        list_chat_history = []

        for message in sendChatHistory:
            if userSendMessages and message.chatted_id == userSendMessages.id:
                data = {
                    'sender': sender_id,
                    'cipher': message.sender_ciphertext,
                }
            elif userReceiveMessages and message.chatted_id == userReceiveMessages.id:
                data = {
                    'sender': recipient_id,
                    'cipher': message.receiver_ciphertext,
                }
            else:
                # Handle the case where the message doesn't belong to either user
                continue
            
            list_chat_history.append(data)
        if reverse:
            return list(reversed(list_chat_history)), total_message_count, rendered_message_count
        else:
            return list_chat_history, total_message_count, rendered_message + rendered_message_count
    else:
        return False, 0, 0


        
        
def changeUserName(user_id, fullname):
    # Query the user id
    user = User.query.filter_by(id=user_id).first()
    
    if user:
        if fullname:
            # Validate the username format (no spaces, only underscores allowed)
            fullname_pattern = re.compile(r'^[a-zA-Z\s]+$')
            if not fullname_pattern.match(fullname):
                return "Special characters are not allowed", 400

            # Update user name
            user.name = fullname
            db.session.commit()
            return "Successfully updated", 200
    else:
        return "User not found", 400

def changeUserUsername(user_id, username):
    # Query the user id
    user = User.query.filter_by(id=user_id).first()
    
    if user:            
        if username:
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return "Special characters and spaces are not allowed", 400
            else:
                existing_username = User.query.filter_by(username=username).first()
                if existing_username:
                    return "Username already exists", 400
                else:
                    # Change the username and save to the database
                    user.username = username
                    db.session.commit()
                    return "Successfully updated", 200
        else:
            return "Username is required", 400
    else:
        return "User not found", 400
    

def changePasswordF(user_id, password, new_password, confirm_password):
    # Query the user id
    user = User.query.filter_by(id=user_id).first()
    
    if user:
        error_messages = []
        password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$')
        # Check if password exists, then append the error message
        if not password:
            error_messages.append({"message": "Password is required", "type": "password"})

        # Validate the password
        if new_password:
            if not password_pattern.match(new_password):
                error_messages.append({"message": "New Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "newPassword"})
            elif len(new_password) < 8:
                error_messages.append({"message": "New Password must be at least 8 characters long.", "type": "newPassword"})
        else:
            error_messages.append({"message": "New Password is required", "type": "newPassword"})

        if confirm_password: 
            if not password_pattern.match(confirm_password):
                error_messages.append({"message": "Confirm Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "type": "confirmPassword"})
            elif len(confirm_password) < 8:
                error_messages.append({"message": "Confirm Password must be at least 8 characters long.", "type": "confirmPassword"})
        else:
            error_messages.append({"message": "Confirm password is required", "type": "confirmPassword"})

        # Check if error_messages array doesn't contain "password" or "confirmPassword" types
        has_password_or_confirm_password_error = any(error.get("type") in ["newPassword", "confirmPassword"] for error in error_messages)

        if not has_password_or_confirm_password_error:
            if new_password and confirm_password and new_password != confirm_password:
                error_messages.append({"message": "Password do not match", "type": "password-not-match"})

        if error_messages:
            return error_messages, 400
        else:
            # Update the user password
            if check_password_hash(user.password, password):
                hashed_password = generate_password_hash(new_password)
                user.password = hashed_password
                db.session.commit()
                return "Change password successfully updated", 200
            else:
                return "Password change failed. Please try again", 400

            # # query a user that match the token
            # user = User.query.filter_by(u=token).first()
            
            # # if statement for user and check the token expiration is greater that now
            # if user and user.token_expiration > datetime.now():
            #     # update the password and token
            #     hashed_password = generate_password_hash(new_password)
            #     user.password = hashed_password
            #     user.token = None
            #     user.token_expiration = None
            #     db.session.commit()
            #     return 'Password successfully reset', 200
            # else:
            #     return 'Invalid or expired token', 400

        
        
    # else: