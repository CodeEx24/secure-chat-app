
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
        private_key=session['private_key']
        public_key=session['public_key']
        return render_template('pages/home.html', private_key=private_key, public_key=public_key)
    
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
        private_key=session['private_key']
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


    