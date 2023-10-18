from extensions import socketio
from flask import session, request, redirect, url_for
from models import User, Messages, db, ChattedUser
from Api.v1.utils import retrieve_chat_history
from flask_socketio import emit, join_room

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
        # # Fetch and emit chat history for this room
        # chat_history = retrieve_chat_history(user.id, chat_user.id)
        # emit('chat_history', {'history': chat_history})
 
        join_room(room)  # Join a room named after the user
    else: 
        return redirect(url_for('home', id=user.id))

# Send the new message here
@socketio.on('send_message')
def handle_new_message(data):
    user_id = session.get('user_id')  # Get the session user id
    chat_user_id = request.args.get('chat_user_id')  # Get the chat user's ID or username from the client's data
    # Get the message and recipient username
    message = data.get('message')
    
     # Get the user object from the database
    user =  User.query.filter_by(id=user_id).first()
    chat_user =  User.query.filter_by(id=chat_user_id).first()
    
    # If both user and chat user existing. Check who has the highest ID value between the two. Then make a room for it in this format lowest-highest
    if user and chat_user:
        if user.id < chat_user.id:
            room = f'{user.id}-{chat_user.id}'
        else:
            room = f'{chat_user.id}-{user.id}'
    
    emit('message', {'sender': user_id, 'message': message}, room=room)
