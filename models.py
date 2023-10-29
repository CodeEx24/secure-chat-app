from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from flask_login import UserMixin

from data.user import user_data
from data.chatted_user import chatted_user_data
from data.question import question_data


db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    public_key = db.Column(db.String, nullable=False)
    key= db.Column(db.String, nullable=False)
    token = db.Column(db.String(128))  # This field will store the reset token
    token_expiration = db.Column(db.DateTime)

class Messages(db.Model):
    __tablename__ = 'Messages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    chatted_id = db.Column(db.Integer, db.ForeignKey('ChattedUser.id'), nullable=False)
    timestamp = db.Column(db.DateTime)
    ciphertext = db.Column(db.String, nullable=False)
        
class ChattedUser(db.Model):
    __tablename__ = 'ChattedUser'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)


class UserKey(db.Model):
    __tablename__ = 'UserKeys'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    private_key = db.Column(db.String, nullable=False)

# # * REQUIRED FOR USERS
class SecurityQuestion(db.Model):
    __tablename__ = 'SecurityQuestion'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False, unique=True)
    question_id = db.Column(db.Integer, db.ForeignKey('Questions.id'), nullable=False)
    answer = db.Column(db.String(255), nullable=False)
    
    
# * REQUIRED FOR USERS
class Question(db.Model):
    __tablename__ = 'Questions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    question = db.Column(db.String(255), nullable=False)
    
# # * REQUIRED FOR USERS
# class Question(db.Model):
#     __tablename__ = 'Questions'

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     question = db.Column(db.String(255), nullable=False)

# class MessageStatus(db.Model):
#     __tablename__ = 'MessageStatus'

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     message_id = db.Column(db.Integer, db.ForeignKey('Messages.id'), nullable=False)
#     receiver_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
#     status = db.Column(db.String(50), nullable=False)  # Status can be 'sent', 'delivered', 'read', etc.

#     def __init__(self, message_id, user_id, status):
#         self.message_id = message_id
#         self.user_id = user_id
#         self.status = status


def init_db(app):
    db.init_app(app)
    with app.app_context():
        inspector = inspect(db.engine)
        if not inspector.has_table('Users'):
            db.create_all()
            create_sample_data()
            
def create_sample_data():
    # for data in user_data:
    #     user = User(**data)
    #     db.session.add(user)
    #     db.session.flush()
        
    # for chatted in chatted_user_data:
    #     chatted_user = ChattedUser(**chatted)
    #     db.session.add(chatted_user)
    #     db.session.flush()
        
    for question in question_data:
        question = Question(**question)
        db.session.add(question)
        db.session.flush()
    db.session.commit()