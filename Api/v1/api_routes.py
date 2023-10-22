# api/api_routes.py
from flask import Blueprint, jsonify, request, redirect, url_for, flash, session, render_template
from models import User, db


# from decorators.auth_decorators import role_required

from .utils import registerUser, sendResetPasswordEmail, resetPassword, loginUser, getUsernameList
from datetime import datetime, timedelta
from flask_mail import Message
from extensions import mail  # Import mail from the mail.py module

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
        print("data: ", data)
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
    
    
@chat_app_api.route('/search')
def searchUsers():

    username = session['user_name']
    query_username = request.args.get('query', '').strip().lower()
    # Request in utils.py for resettingPassword
    result, status_code = getUsernameList(username, query_username)
    
    response_data = {"result": result} if status_code == 200 else {"errors": result}

    return jsonify(response_data), status_code


# Define the route for /username
@chat_app_api.route('/<string:username>')
def chat_with_user(username):
    # Retrieve the user from the database
    user = User.query.filter_by(username=username).first()

    if user:
        # Redirect to the chat page with the specified user
        return redirect(url_for('chat', id=user.id))

    # Handle the case where the user doesn't exist
    return "User not found", 404
    
    
# Define the route for /username
@chat_app_api.route('/get_rsa_keys')
def getRSA():
    publicKeyStr ='-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqEXgKViXKvj5dJZ+9xA 4VtVtstg11pBxvepNevd8eWLMzV8wfmBE3KZSsV9erb226sAp2DIlImAjOcNE04n r0Bi4KMd7bHU8sCUpgxNw/H1wyrA6QXQ2cS8GN5kzMcDMHtILH3y7p/tpYKeS1YK oIVJhybug8MFgkdaR07Dl2haOni2GTzBTc50crQx5yjiXT8Gb+aK2Y3CD6+H11ys myOnplIOXixmPaj3Fu0nF+6l4kCy39rFLkA1KjieE6O6Gr2k9k9p93FHjDcxNZAy 3zgIJJzgPsjGe0HQZA8uw5pf3V9MwmtkVv8A4fRus7TyAlA0U4Wxqrzv0tFxucex vQIDAQAB -----END PUBLIC KEY-----';

    privateKeyStr ='-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAt1zj1f+w0I6m5tM0qLx6uMoXhXx72/B3Jlyiccvd5ME7fdvS U9FF4QaImnUSdX9xvGxKamTM7ktmZwiKj2ouHG+kVyqZq/PHlFRB8qGRPqYnQR2c OvyBX8h/Y3UJetmZOijeQJeYWZeaNNnGb/KOyY7RvLCYrz2eeTPb63UDoSgVW/7w 1Ijljf0m8/NU5G0j61B5WVs2HY5HA2mrJlRd3rUX/KBOxOa+u8itmfC+QWB8nNvf HTan9ebahIHpKwaIIe2kdDAKNXvxzD/HUI/gwL3BJ59nfH74TbMhHPHcE7gp+Ic5 jiPEtfCTLW9DM4X1CNkAmyEZ7oz7gO+TKBs0ywIDAQABAoIBADFzuPK/KeWlg3ff YGVdp89smZljsFfp64iKFTmRnP+T6cKQ5ZG7cBg3VeIqTtcnjvodTpiRJP/jj/Ob xxrUrSj4Jx9nGtjYP2xOqRaR4oU99HpITRlPfmjhvxGIwAzE4OFhokdTW0BWdb1p Om54wW+0t/YmvpcMjE/t35MKFPeCTgUma9GXoW6oNh22vWTJ7kQVZgSQKizIcppE D1JyZax1bbix712P11LQYN+el83Ez55l2YQWMX8nuRk5UptX6H7Qyd0urZqMGCb/ iOCBnH5EIuMgmHZqTYeP52vRYCBfDZ7qGu3PpCE2ec5JuHBtn0RtaO7TwJ5WE9Nc +nhsIokCgYEA0IyOkG7+IwEIbHsvgCsVmUJTISpmWQ5k35D6s60P8H3NcNIGZdZ2 MTjTcdxvcHkCOv8YTNLs/3sWvRiJ72YAGEg1Qcl25Om31eDths5QVV4p5gKdyaCQ JLx19TKQwT43qx6htt9tSJOTo53iidmD7UppuuzLdMDM21eX0p30g38CgYEA4RVN V0HY/Hs7qJXdaF0Pt0x8o/o0P4U5X8KigXtbZY81OarnMbguO8GAxjC3aLAvmT1l miuWH7C33ZBRFQD+rQxZ7VlcOJ0u+XJUJrK7kZX8Vud8pbz0op1BEWKnunLK7XMN LwaQGpahMoXARo0mK+xs2SLu5CNicUdMSIzzxLUCgYAniP3d06zJ5gA60H+IxKIr k68+slMEvv3QhCOCvGQxKygvIyGjXKy7WBJ9m1Rk9gu+M23f4nybUjJVVrmPcL7D 26x89Dxd2RDIswNUcvg3tsoqmIRhHNc2n6OdACEBAVJ8VipCCMkm4RM0CVJQ37Nq 4Jh6nzlSwNoVGt3lR5x68QKBgG821VYuBQcL5PhxxEqS4PcS5esn77ULIMQ+KYmM 6CYQUp5B4aZheQaxn+1NmPIzS/GNsqwwqSbTbKYfbtDQAwaCOdTa+IRItjMu2IGe gqt2zo4qJx7FdKL8zG/IrVOk8LvOw07fEUjx8IhEKjMx/xBo64eGiT9UdInATuLy MmiZAoGBALdmaDoB2a5PegLg0lI0i6relHmZlFHvRTW0UC4Son5x51n/seFoPWt2 Dq7EcidnKC2FtsbdKSzPaXe4RVrvM8smcSEzctVCpowpW1T6ZhKxCcsuZYItrK5K G5Axnazt11YQhax4+v2V/uLrk5LVlchiDhneuBttIN3q/M0mi5so -----END RSA PRIVATE KEY-----';
    # Retrieve the user from the database
    
    return jsonify(publicKey=publicKeyStr, privateKey=privateKeyStr)

# student_api.py (continued)