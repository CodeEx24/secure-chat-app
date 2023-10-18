from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet

from models import db, User, Messages, ChattedUser, SecurityQuestion
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
    
    print("private_key: ", private_key)
    print("public_key: ", public_key)
    return private_key, public_key

# Function to encrypt a private key using Fernet
def encrypt_private_key(private_key, encryption_key):
    cipher_suite = Fernet(encryption_key)
    encrypted_private_key = cipher_suite.encrypt(private_key)
    return encrypted_private_key

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
        return "Successfully login", 200
    else:
        if username and password:
            # error message append the invalid email pass
            error_messages.append({"message": "Invalid email or password", "type": "invalid"})
    if error_messages:
        return error_messages, 400

def registerUser(email, username, password, confirm_password,  answer, question=None):

    # Initialize an empty list to store error messages
    error_messages = []

    print("security_question: ", question)
    print("answer: ", answer)
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
    
    print("private_key_str: ", private_key_str)
    print("public_key_str: ", public_key_str)
    
    print("private_key: ", private_key)
    print("public_key: ", public_key)
    # encrypted_private_key= encrypt_private_key(private_key)
    hashed_password = generate_password_hash(password)
    hashed_answer = generate_password_hash(answer)
    
 
    
   # If no errors, proceed with user registration
    new_user = User(email=email, username=username, password=hashed_password, public_key= public_key_str, private_key=private_key )
    new_security_question = SecurityQuestion(user_id=new_user.id, question_id=question, answer=hashed_answer)

    # Save the user to the database
    db.session.add(new_user)
    db.session.add(new_security_question)
    db.session.commit()
    
    # ... the rest of your registration code ...
  
    return "Account successfully created", 400


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