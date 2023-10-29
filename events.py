from extensions import socketio
from flask import session, request, redirect, url_for
from models import User, Messages, db, ChattedUser
from Api.v1.utils import retrieve_chat_history
from flask_socketio import emit, join_room
from datetime import datetime


@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')  # Get the session user id
    chat_user_id = request.args.get('chat_user_id')  # Get the chat user's ID or username from the client's data
    # Get the user object from the database
    user =  User.query.filter_by(id=user_id).first()
    chat_user =  User.query.filter_by(id=chat_user_id).first()
    
    # If both user and chat user existing. Check who has the highest ID value between the two. Then make a room for it in this format lowest-highest
    if user and chat_user:
        if user.id < chat_user.id:
            room = f'{user.id}-{chat_user.id}'
        else:
            room = f'{chat_user.id}-{user.id}'
        print("ROOM: ", room)
 
        join_room(room)  # Join a room named after the user
        
        # Fetch and emit chat history for this room
        # chat_history = retrieve_chat_history(user.id, chat_user.id)
        # emit('chat_history', {'history': chat_history})
    else: 
        return redirect(url_for('home', id=user.id))

# Send the new message here
@socketio.on('send_message')
def handle_new_message(data):
    user_id = session.get('user_id')  # Get the session user id
    chat_user_id = request.args.get('chat_user_id')  # Get the chat user's ID or username from the client's data
    print("chat_user_id: ", chat_user_id)
    
    # Get the message and recipient username
    message = data.get('message')
    print("MESSAGE: ", message)
    
    # Get the user object from the database
    user =  User.query.filter_by(id=user_id).first()
    chat_user =  User.query.filter_by(id=chat_user_id).first()
    
    print("USER: ", user, "CHAT USER: ", chat_user)
    
    if user and chat_user:
        if user.id < chat_user.id:
            room = f'{user.id}-{chat_user.id}'
        else:
            room = f'{chat_user.id}-{user.id}'

        print("ROOM: ", room)
        
        # Check if a chat user already exists
        chatted_user = ChattedUser.query.filter_by(sender_id=user.id, recipient_id=chat_user.id).first()
        current_time = datetime.now()

        # If chatted user exist save the message in database
        if chatted_user:
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, ciphertext=message)
            db.session.add(messageDetails)
            db.session.commit()  # Commi
        else:
            # Create a chatted user
            create_chat_user = ChattedUser(sender_id=user.id, recipient_id=chat_user.id)
            db.session.add(create_chat_user)
            db.session.commit()
            
            chatted_user = ChattedUser.query.filter_by(sender_id=user.id, recipient_id=chat_user.id).first()
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, ciphertext=message)
            db.session.add(messageDetails)
            db.session.commit()
        # Emit the message to the chat room
        print("messageDetails: ", messageDetails)
        emit('message', {'sender': user_id, 'message': messageDetails.ciphertext}, room=room)
        
        
        