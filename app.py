
from flask import Flask, render_template, redirect, url_for, session
from flask_cors import CORS

import os
from dotenv import load_dotenv

from models import init_db
# from flask_jwt_extended import JWTManager

from decorators.auth_decorators import preventAuthenticated, userRequired
from datetime import  timedelta
from extensions import mail  # Import mail from the mail.py module
from events import socketio
from flask_socketio import SocketIO

from Api.v1.api_routes import chat_app_api


def create_app():
    load_dotenv()  # Load environment variables from .env file
    app = Flask(__name__) # Initialize the application 
    
    # socketio = SocketIO(app, cors_allowed_origins=allowed_origins) # Initialize Flask-SocketIO

    # cache.init_app(app)

    # Allowed third party apps
    # jwt = JWTManager(app)
        # Configure Flask-Mail for sending emails
    app.config['MAIL_SERVER'] =  os.getenv("MAIL_SERVER")
    app.config['MAIL_PORT'] =  os.getenv("MAIL_PORT")
    app.config['MAIL_USERNAME'] =  os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['TEMPLATES_AUTO_RELOAD'] = True 
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    init_db(app)
    # Configure Flask-Mail for sending emails

    # app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    mail.init_app(app)
    socketio.init_app(app)
    
    chat_api_base_url = os.getenv("CHAT_API_BASE_URL")

    
    # @app.context_processor
    # def custom_context_processor():
    #     authenticated = False
    #     if 'user_role' in session:
    #         authenticated = True
    #     return {'authenticated': authenticated}
    
    @app.before_request
    def before_request():
        session.permanent=True
        pass
    
    # ===========================================================================
    # ROUTING FOR THE APPLICATION (http:localhost:3000)

    @app.route('/')
    @preventAuthenticated
    def login():
        return render_template('pages/login.html')
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))  
    
    
    @app.route('/register')
    @preventAuthenticated
    def register():
        return render_template('pages/register.html')
    
    @app.route('/forgot-password')
    @preventAuthenticated
    def forgotPassword():
        return render_template('pages/forgot_password.html', chat_api_base_url=chat_api_base_url)
    
    @app.route('/home')
    @userRequired
    def home():
        return render_template('pages/home.html')
    
    @app.route('/practice')
    @userRequired
    def practice():
        private_key=session['private_key']
        public_key=session['public_key']
        return render_template('pages/practice.html', private_key=private_key, public_key=public_key)
    
    @app.route('/practice2')
    @userRequired
    def practice2():
        
        return render_template('pages/practice2.html')
        
        
    # Define the chat route
    @app.route('/chat/<int:id>')
    def chat(id):
        # Your chat logic goes here
        private_key='-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAjonBGRB4Vggl875P5EvMCuWk9M3aiIWc7pveMp1n7ZRH0NWz u19BVTT6Mmydzkm0UXWHX9IR2TfOMebMPgV6t8j+5sU53HjPSQ3KmLpF4de+vww7 Tox/HXwhm6EQ420ngonzyvsWOqLQ4SBNH4Vx9kxXJX7/ZvFLLqLA/ZnkYmn3+Nti owRXUzw35pP9juKhmqS9dh75iufyNjVtnLp8Em8zP6X84R7Kuoqezg1sfjtGjWCq fnwbZTdPOXEUdcFpYzejI9vKcUu/cwjTlRWDhjGE58HhiIFV4zI36gXuB6TPx6xT 89yXUijHIYrEFpEoeJa2rZ4Cdxw+2mg7Gz4VgQIDAQABAoIBAAVdTN2nH4hJXThL sNEMQz0jwG4QM0nREYNvbVDlWKx52KwU5uNF5f0Rddsg+F1zq6wnKrWh/9b3gTSi lYw+A4zYLTO9N3zDNTXwJXBTDl8+Eek5yh+eLQiMi+1CBhMxH/wLOhgpFACX8RmP 8CcgDBZzcBIyseULbsNuD6pbuNs1SGVrrUK6nFvhXV638t8VodXj7uixtl7Dywq9 x8i4HV0ZMssSruHVjLYMt+YlI3greyCddYvITWNQuHfVjOdEAXJltatrjb+5Wxmf GrdNu/It6S5J9T1S/Qq2P2QuUO0qUKMdlkR7CdlpfsTv+Q7VmbaSl4qOOn5NNZtb squWCdMCgYEAvkjlXHI8VwPfvuO0/msrdwUiVYsS0tFmirqoj+LtQXpwQTv5YTbR dvuaPjdt85XHaSSihMp758eFEYCoEAoRCtyGgbBte84rNbfR3qNx2rtmjQWLq2c/ 23Q7ZFTh09iLjvgtkJIreUHlvp5nIBv61OUvh9+AL8c6NeT9vRDSFaMCgYEAv8OR 5i5Nuf4fKINHc+aVFFGM6N1wMuwjcRRmkI6v5j3Y3YoV9duO0H35JyeC0GxtgLbI 0i2oysZsQbZK1bvgdEfHSHZ4M59ugM7CDafZZaYDjH3HnpDpN9SzdJ8VWlQgfLR8 ffBExwpCFI8aF58u15Rox58s0NDQw2lsJmlrsosCgYBHMi0nNtLe1+M6oCZTXzPn F3OuQBft602LsKVrGMQe0Ln5noADYKhk9WTTzJeGIU94Rq3MM5rCsUNXtiSrw6h2 wOZO1f1Q6mX+dmW/ALaT2bRYJXAJ1NruuIGUW7IXOpmVB8S8qAQ+HWrhtJDvUai7 SXlMRFLJDaj5C1HpEMcaMwKBgG6DfezC2KaMzlYhuicQRvArw2JcY5HlRtOfZzB+ Gt8822Npdhh3jQmY3+LxwVDue/kG3htKlxEtYyxHqz8cBFHfH/kh1Uoi4qM3BNyr 0/zhvP/VaRp39v/nA/j8yWiCPSrBNVG7C1gOEGEay3W7llpFPFF26XP6M6W6dsp4 TMnbAoGBAIr/u3k2jJML4INHW0NwWRmXFP1WxnSwEzXT3XCqv55CE6ohzAKYjDMc xWHTCapOzD7adHG226b48O3X4Wdqu9yii+b7wrN3ZPtAdOkXoxrRgFNF28WV2mwB ulJlkZI7KGUQYYoB8hZij8vMlQdMktsBBrGatAL9JIuSB8vtM90r -----END RSA PRIVATE KEY-----'
        public_key=session['public_key']
        return render_template('pages/chat.html', id=id, private_key=private_key, public_key=public_key)

    if __name__ == '__main__':
        app.run(debug=True)



    # ========================================================================
    # Register the API blueprint

    app.register_blueprint(chat_app_api, url_prefix=chat_api_base_url)

    @app.route('/page_not_found')  # Define an actual route
    def page_not_found():
        return handle_404_error(None)

    @app.errorhandler(404)
    def handle_404_error(e):
        return render_template('pages/404.html'), 404


    if __name__ == '__main__':
        socketio.run(app, debug=True) # Start the application with Socket.IO in debug mode

    return app


    