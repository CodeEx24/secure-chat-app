# api/api_routes.py
from flask import Blueprint, jsonify, request, redirect, url_for, flash, session, render_template
from models import User, db, Question


# from decorators.auth_decorators import role_required

from .utils import registerUser, sendResetPasswordEmail, resetPassword, loginUser, getUsernameList, changeUserName, changeUserUsername, changePasswordF
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

        result, status_code = loginUser(username, password)
        response_data = {"result": result} if status_code == 200 else {"errors": result}
     
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
    if request.method == 'POST':
        # Get the form new-password and confirm-password
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
    # Retrieve the user from the database
    user = User.query.filter_by(username=username).first()

    if user:
        # Redirect to the chat page with the specified user
        return redirect(url_for('chat', id=user.id))

    # Handle the case where the user doesn't exist
    return "User not found", 404
    
# Define the route for /username
@chat_app_api.route('/security-question')
def fetchSecurityQuestions():
    # Retrieve the user from the database
    data_questions = Question.query.filter_by().all()
    if data_questions:
            list_data_class_grade = []

            for data in data_questions:
                data = {
                    "id": data.id,
                    "question": data.question
                }
                list_data_class_grade.append(data)
    # Return all question as json object
    return jsonify(list_data_class_grade), 200

    
# Define the route for /username
@chat_app_api.route('/change/name', methods=['GET', 'POST'])
def updateUserName():

    if request.method == 'POST':
        data = request.get_json()
        print('data: ', data)
        user_id = session['user_id']
        print("user_id: ", user_id)
        fullname = data['fullname']
        print("fullname: ", fullname)
   
   
        result, status_code = changeUserName(user_id ,fullname)

        response_data = {"result": result} if status_code == 200 else {"error": result}

        return jsonify(response_data), status_code

# Define the route for /username
@chat_app_api.route('/change/username', methods=['GET', 'POST'])
def updateUserUsername():
    if request.method == 'POST':
        data = request.get_json() 
        user_id = session['user_id']  
        username = data['username']   
   
        result, status_code = changeUserUsername(user_id ,username)
        response_data = {"result": result} if status_code == 200 else {"error": result}
        return jsonify(response_data), status_code

    
# Define the route for /username
@chat_app_api.route('/change/password', methods=['GET', 'POST'])
def changePassword():
    if request.method == 'POST':
        data = request.get_json() 
        user_id = session['user_id']  
        current_password = data['currentPassword']   
        new_password = data['newPassword']  
        confirm_password = data['confirmPassword']  
   
        result, status_code = changePasswordF(user_id ,current_password, new_password, confirm_password)
        response_data = {"result": result} if status_code == 200 else {"errors": result}
        return jsonify(response_data), status_code

    
# Define the route for /username
@chat_app_api.route('/get_rsa_keys')
def getRSA():
    publicKeyStr ='-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMTDArkZRIxEnMAxkv9X iDbp+9kM0AeoBg0zFWEpflSJ0m0b6SjTkUnarpCkOKnHJ1C0zQyz6ceYtoREcEcV M3dVc0QsWjcj4h7ejmBlVvhZLkaRdpOm6Unrmgt4zxNOzhhurNJ/n8Qe7dXUnanZ a/PxEQgRvsJ72fG7Dq1kpmQGO9OeCVAOEkAogb9AkE1skcEBBd1fnOASjCASaGK6 nniXOpyB4mHiLA6dUBP7jBXPHV4oZYRtmoXsEw5eiw6GSdUgfoif57ksXOz9qzr1 Yhqajl5r4Ce/RhH7uSNgi+mv1xInoDIS3d7xgV+Y/jBPzimv3/Kdo+uCk1PCm6Bh 9wIDAQAB -----END PUBLIC KEY-----';

    privateKeyStr =b'-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAwMTDArkZRIxEnMAxkv9XiDbp+9kM0AeoBg0zFWEpflSJ0m0b\n6SjTkUnarpCkOKnHJ1C0zQyz6ceYtoREcEcVM3dVc0QsWjcj4h7ejmBlVvhZLkaR\ndpOm6Unrmgt4zxNOzhhurNJ/n8Qe7dXUnanZa/PxEQgRvsJ72fG7Dq1kpmQGO9Oe\nCVAOEkAogb9AkE1skcEBBd1fnOASjCASaGK6nniXOpyB4mHiLA6dUBP7jBXPHV4o\nZYRtmoXsEw5eiw6GSdUgfoif57ksXOz9qzr1Yhqajl5r4Ce/RhH7uSNgi+mv1xIn\noDIS3d7xgV+Y/jBPzimv3/Kdo+uCk1PCm6Bh9wIDAQABAoIBAEc0BrJJS7+JrkhW\nJ5mcDqmGWyxHMpfe1B4UHxPdFVYQBO6AlegsR+WpKYkEbVxuvdzUT0xUTlpiexKj\nzaHJZ9fgUuRmQJm8N1ltPJjLm3Mh/dL9hvqNNICEaO24IhIfGCNBXBQjFrgdWa1R\nKB1qoSBidV9sox1auiO5SfZ0brKUp3pyhivyy0DOFaPM9aeuTQVU0x+DIwjYVMGf\npJaDQS2FyqT+iPMiVZtdZICDGGmi2vdHu9KLkIBA1zUHbtEKTo1jwrqE9uOaILvS\nVNpR/Wdf36g9+4/E5t9oh52WFyaQcly3BVpsda4AxO40iR0XTH57LxHd5netyFka\nPOMCMs0CgYEAxPwdSZVSR3U3RWwXVXS5hUpMGonfT6vNbTldyshTIBr/notMRrQG\nxW2C0I5FVXfws1VzJiLbpMiwotLMQ8/RM5Mvfws5a00KUu55xyZ+tUS105AViuPE\ng/ZLTRISKNir3q3HCgbaGpn4a28+78I0jzTKR6jKK8jSaCtPaze8LuUCgYEA+oVI\nCMLZ6GUb+zEqliJcuvT4sHvPVck4sx/bJ+HMW+JT0vsoNw9rm2rsJEHvjJGbUUIq\nZUy/0Rt3A3zQ2b8y26EDFTAo70cPJNVaCA9UrJowZzOb3Ai1SemppHOZx0M7m4sL\n/cdZDtVLbZLUG95XM2ahfb8AotLaHeRex+h446sCgYAIRlLwoV4odEsTFnxQcavN\nZpaV0s7XqO7jNLK07v9W7Otp/I4CtlNGfdgt7JwLABPTZLaGlpZFcMzCujosaxFt\nqjQnkRAjasQRQcVJ0VsnQDCnJ3lQMUszA+ib3zN2Fcv6ebBPwoPs9CTUVoL9TVop\n3dzVb8i2WCRGjfMzHM9B5QKBgBfx1UjBFwLXZy1DLcbb0fEsqPh1XQPeD8VPLitJ\nsba2kzx/NQDOQILCXX+5raPJ5waFRHgaNdtOvLlgnLWzSLElWp4T1FXKfPAQVGKg\n1H8K3cV/cU4+ptVBuC03v2MEUhYz3BmNjD2WtXbrqcpgHgWTsavLLcxiSubAhS6m\nUaexAoGAQPGcNlOcD2c3jvM4rLLzw2M04H3Z6sCmLgB1Letb5SbtAkpxCR/KbKP/\nf2PjLuBKcSFTRtd1qeR3Nncc+XXBTDSUxr8PsOkVgPHjnJIdn8LJDUwbFAl8fMgz\nwRAusIIKEsO2WRdiNFFy1x0NJDXjbgm91GcIwlhwsKb32NkJ5k4=\n-----END RSA PRIVATE KEY-----';
    # Retrieve the user from the database
    
    return jsonify(publicKey=publicKeyStr, privateKey=privateKeyStr)

# student_api.py (continued)