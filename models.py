from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from flask_login import UserMixin

from data.user import user_data

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    public_key = db.Column(db.String, nullable=False)
    private_key = db.Column(db.String, nullable=False)
    token = db.Column(db.String(128))  # This field will store the reset token
    token_expiration = db.Column(db.DateTime)
    

    def __init__(self, username, password, email, public_key, private_key):
        self.username = username
        self.password = password
        self.email = email
        self.public_key = public_key
        self.private_key = private_key

class Message(db.Model):
    __tablename__ = 'Messages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    timestamp = db.Column(db.DateTime)
    ciphertext = db.Column(db.String, nullable=False)

    def __init__(self, sender_id, recipient_id, timestamp, ciphertext):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.timestamp = timestamp
        self.ciphertext = ciphertext


def init_db(app):
    db.init_app(app)
    with app.app_context():
        inspector = inspect(db.engine)
        if not inspector.has_table('Users'):
            db.create_all()
            create_sample_data()
            
def create_sample_data():
    for data in user_data:
        user = User(**data)
        db.session.add(user)
        
    db.session.commit()