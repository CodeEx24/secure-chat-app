# api/api_routes.py
from flask import Blueprint, jsonify, request, redirect, url_for, flash, session, render_template
from models import User, db


# from decorators.auth_decorators import role_required

from .utils import registerUser, sendResetPasswordEmail, resetPassword, loginUser
from datetime import datetime, timedelta
from flask_mail import Message
from mail import mail  # Import mail from the mail.py module

import os
import secrets

chat_api_base_url = os.getenv("CHAT_API_BASE_URL")

chat_app_api = Blueprint('chat_app_api', __name__)


@chat_app_api.route('/login', methods=['POST'])
def login():
   
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print("GET IT ")
        result, status_code = loginUser(username, password)
        response_data = {"result": result} if status_code == 200 else {"errors": result}
        print(response_data)
        return jsonify(response_data), status_code

        
@chat_app_api.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.form  # Get the form data as a dictionary
        result, status_code = registerUser(**data)

        response_data = {"result": result} if status_code == 200 else {"errors": result}
        return jsonify(response_data), status_code


@chat_app_api.route('/reset_password', methods=['POST'])
def forgotPasswordRequest():
    print("INSIDE HERE:")
    if request.method == 'POST':
        email = request.form['email']
         # Call the registerUser function to handle registration
        result, status_code = sendResetPasswordEmail(email)
       
        response_data = {"message": result} if status_code == 200 else {"error": result}
        return jsonify(response_data), status_code


        
# Step 6: Create a route to render the password reset confirmation form
@chat_app_api.route('/reset_password_confirm/<token>', methods=['GET', 'POST'])
def resetPasswordConfirm(token):
    if request.method == 'POST':
        # Get the form new-password and confirm-password
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
        
        # Request in utils.py for resettingPassword
        result, status_code = resetPassword(token, new_password, confirm_password)
        response_data = {"message": result} if status_code == 200 else {"errors": result}
        return jsonify(response_data), status_code
    else:
        user = User.query.filter_by(token=token).first()
        if user and user.token_expiration > datetime.now():
            return render_template('pages/forgot_password_confirm.html', token=token, chat_api_base_url=chat_api_base_url)
        else:
            return render_template('pages/404.html')
    
# student_api.py (continued)