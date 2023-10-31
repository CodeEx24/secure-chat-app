from extensions import socketio
from flask import session, request, redirect, url_for
from models import User, Messages, db, ChattedUser
from Api.v1.utils import retrieve_chat_history
from flask_socketio import emit, join_room
from datetime import datetime
from sqlalchemy import or_

from flask_socketio import emit
from datetime import datetime
from sqlalchemy import or_
from flask_socketio import emit, join_room


@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    chat_user_id = request.args.get('chat_user_id')
    user = User.query.get(user_id)
    
    if chat_user_id:
        print("IN CHAT USER ID: ", chat_user_id)
        current_chat_user = User.query.get(chat_user_id)
        list_chatted_user = []

        if user:
            chatted_user = ChattedUser.query.filter(
                or_(
                    ChattedUser.sender_id == user_id,
                    ChattedUser.recipient_id == user_id
                )
            ).all()
            for chat in chatted_user:
                if chat.sender_id == user_id:
                    if chat.recipient_id in [user['id'] for user in list_chatted_user]:
                        continue
                    else:
                        chat2 = ChattedUser.query.filter(
                            ChattedUser.recipient_id == chat.sender_id,
                            ChattedUser.sender_id == chat.recipient_id
                        ).first()
                        chat_user = User.query.get(chat.recipient_id)
                        room = f'{min(user.id, chat_user.id)}-{max(user.id, chat_user.id)}'
                        join_room(room)
                        message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc()).first()

                        if chat2:
                            message2 = Messages.query.filter_by(chatted_id=chat2.id).order_by(Messages.timestamp.desc()).first()

                            if message2 and message.timestamp >= message2.timestamp:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message.id,
                                    'sender_id': chat.sender_id,
                                    'timestamp': message.timestamp.isoformat(),
                                    'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                                }
                            else:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message2.id,
                                    'sender_id': chat2.sender_id,
                                    'timestamp': message2.timestamp.isoformat(),
                                    'message': message2.sender_ciphertext if chat2.sender_id == user.id else message2.receiver_ciphertext,
                                }
                        else:
                            dict_chat_user = {
                                'id': chat_user.id,
                                'username': chat_user.username,
                                'public_key': chat_user.public_key,
                                'last_message_id': message.id,
                                'sender_id': chat.sender_id,
                                'timestamp': message.timestamp.isoformat(),
                                'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                            }
                        list_chatted_user.append(dict_chat_user)
                else:
                    if chat.sender_id in [user['id'] for user in list_chatted_user]:
                        continue
                    else:
                        chat2 = ChattedUser.query.filter(
                            ChattedUser.recipient_id == chat.sender_id,
                            ChattedUser.sender_id == chat.recipient_id
                        ).first()
                        chat_user = User.query.get(chat.sender_id)
                        room = f'{min(user.id, chat_user.id)}-{max(user.id, chat_user.id)}'
                        join_room(room)
                        message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc()).first()

                        if chat2:
                            message2 = Messages.query.filter_by(chatted_id=chat2.id).order_by(Messages.timestamp.desc()).first()

                            if message2 and message.timestamp >= message2.timestamp:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message.id,
                                    'sender_id': chat.sender_id,
                                    'timestamp': message.timestamp.isoformat(),
                                    'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                                }
                            else:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message2.id,
                                    'sender_id': chat2.sender_id,
                                    'timestamp': message2.timestamp.isoformat(),
                                    'message': message2.sender_ciphertext if chat2.sender_id == user.id else message2.receiver_ciphertext,
                                }
                        else:
                            dict_chat_user = {
                                'id': chat_user.id,
                                'username': chat_user.username,
                                'public_key': chat_user.public_key,
                                'last_message_id': message.id,
                                'sender_id': chat.sender_id,
                                'timestamp': message.timestamp.isoformat(),
                                'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                            }
                        list_chatted_user.append(dict_chat_user)

        if user and current_chat_user:
            room = f'{min(user.id, current_chat_user.id)}-{max(user.id, current_chat_user.id)}'
            join_room(room)
            current_chat_public_key = current_chat_user.public_key
            chat_history = retrieve_chat_history(user.id, current_chat_user.id)
          
            sort_chatted_user = sorted(list_chatted_user, key=lambda x: x['timestamp'], reverse=True)
          
            emit('chat_details', {
                'current_chat_public_key': current_chat_public_key,
                'current_chat_username': current_chat_user.username,
                'chat_history': chat_history,
                'chat_user': sort_chatted_user
            })

    else:
        list_chatted_user = []
        if user:
            chatted_user = ChattedUser.query.filter(
                or_(
                    ChattedUser.sender_id == user_id,
                    ChattedUser.recipient_id == user_id
                )
            ).all()
            for chat in chatted_user:
                if chat.sender_id == user_id:
                    if chat.recipient_id in [user['id'] for user in list_chatted_user]:
                        continue
                    else:
                        chat2 = ChattedUser.query.filter(
                            ChattedUser.recipient_id == chat.sender_id,
                            ChattedUser.sender_id == chat.recipient_id
                        ).first()
                        chat_user = User.query.get(chat.recipient_id)
                        message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc()).first()

                        if chat2:
                            message2 = Messages.query.filter_by(chatted_id=chat2.id).order_by(Messages.timestamp.desc()).first()

                            if message2 and message.timestamp >= message2.timestamp:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message.id,
                                    'sender_id': chat.sender_id,
                                    'timestamp': message.timestamp.isoformat(), 
                                    'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext
                                }
                            else:
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message2.id,
                                    'sender_id': chat2.sender_id,
                                    'timestamp': message2.timestamp.isoformat(), 
                                    'message': message2.sender_ciphertext if chat2.sender_id == user.id else message2.receiver_ciphertext
                                }
                        else:
                            dict_chat_user = {
                                'id': chat_user.id,
                                'username': chat_user.username,
                                'public_key': chat_user.public_key,
                                'last_message_id': message.id,
                                'sender_id': chat.sender_id,
                                'timestamp': message.timestamp.isoformat(), 
                                'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                                
                            }
                        list_chatted_user.append(dict_chat_user)
            # Sort the list based on the timestamp in descending order
            sort_chatted_user = sorted(list_chatted_user, key=lambda x: x['timestamp'], reverse=True)
            emit('chat_details', {'chat_user': sort_chatted_user, 'user_id': user_id})


# CONNECTED CHATS WITH USER ID
# @socketio.on('connect')
# def handle_connect():
#     user_id = session.get('user_id')  # Get the session user id
#     chat_user_id = request.args.get('chat_user_id')  # Get the chat user's ID or username from the client's data
#     # Get the user object from the database
#     user =  User.query.filter_by(id=user_id).first()
#     chat_user =  User.query.filter_by(id=chat_user_id).first()
    
#     # If both user and chat user existing. Check who has the highest ID value between the two. Then make a room for it in this format lowest-highest
#     if user and chat_user:
#         if user.id < chat_user.id:
#             room = f'{user.id}-{chat_user.id}'
#         else:
#             room = f'{chat_user.id}-{user.id}'
#         print("ROOM: ", room)
 
#         join_room(room)  # Join a room named after the user
        
#         # Get chat user public key
#         chat_user_public_key = chat_user.public_key 
        
#          # Fetch and emit chat history for this room
#         chat_history = retrieve_chat_history(user.id, chat_user.id)
#         # Emit the public key of chat user and chat history
#         emit('chat_details', {'chat_user_public_key': chat_user_public_key, 'chat_history': chat_history})
        
       
#         # emit('chat_history', {'chat_history': chat_history})
#     else: 
#         return redirect(url_for('home', id=user.id))

# Send the new message here
@socketio.on('send_message')
def handle_new_message(data):
    user_id = session.get('user_id')  # Get the session user id
    chat_user_id = request.args.get('chat_user_id')  # Get the chat user's ID or username from the client's data
    # print("chat_user_id: ", chat_user_id)
    
    # Get the message and recipient username
    senderEncryptedMessage = data.get('senderEncryptedMessage')
    receiverEncryptedMessage = data.get('receiverEncryptedMessage')
    # print("senderEncryptedMessage: ", senderEncryptedMessage)
    # print("receiverEncryptedMessage: ", receiverEncryptedMessage)
    
    # Get the user object from the database
    user =  User.query.filter_by(id=user_id).first()
    chat_user =  User.query.filter_by(id=chat_user_id).first()
    
    # print("USER: ", user, "CHAT USER: ", chat_user)
    
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
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, sender_ciphertext=senderEncryptedMessage, receiver_ciphertext=receiverEncryptedMessage)
            db.session.add(messageDetails)
            db.session.commit()  # Commi
        else:
            # Create a chatted user
            create_chat_user = ChattedUser(sender_id=user.id, recipient_id=chat_user.id)
            db.session.add(create_chat_user)
            db.session.commit()
            
            chatted_user = ChattedUser.query.filter_by(sender_id=user.id, recipient_id=chat_user.id).first()
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, sender_ciphertext=senderEncryptedMessage, receiver_ciphertext=receiverEncryptedMessage)
            db.session.add(messageDetails)
            db.session.commit()
        # Emit the message to the chat room
        
        # print("messageDetails: ", messageDetails)
        emit('message', {'sender': user_id, 'receiver': chatted_user.recipient_id, 'senderCipher': messageDetails.sender_ciphertext, 'receiverCipher': messageDetails.receiver_ciphertext}, room=room)
        
        
        
        
# TEMPORARY CODE FOR RETRIEVING SIDEBAR:
# @socketio.on('connect')
# def handle_connect():
#     user_id = session.get('user_id')  # Get the session user id
#     user = User.query.filter_by(id=user_id).first()
#     list_chatted_user = []

#     if user:
#         chatted_user = db.session.query(ChattedUser).filter(
#             or_(
#                 ChattedUser.sender_id == user_id,
#                 ChattedUser.recipient_id == user_id
#             )
#         ).all()
#         # List of dictionaries with 'id', 'username', and 'public_key' attributes
#         for chat in chatted_user:
#             # check if chatted user is sender_id or recipient_id is different from user_id. If yes, append that user to list_chatted_user
#             if chat.sender_id == user_id:
#                 # Check if chat.recipient_id is already existing in list_chatted_user
#                 if chat.recipient_id in [user['id'] for user in list_chatted_user]:
#                     continue
#                 else:
#                     chat2 = db.session.query(ChattedUser).filter(ChattedUser.recipient_id == chat.recipient_id, ChattedUser.sender_id == chat.sender_id).first()
#                     chat_user = User.query.filter_by(id=chat.recipient_id).first()
#                     # Get the latest messages 
#                     message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc().desc()).first()
#                     message2 = Messages.query.filter_by(chatted_id=chat2.id).order_by(Messages.timestamp.desc().desc()).first()
                  
#                     if message.timestamp >= message2.timestamp:
#                         dict_chat_user = {
#                             'id': chat_user.id,
#                             'username': chat_user.username,
#                             'public_key': chat_user.public_key,
#                             'last_message_id': message.id,
#                             'sender_id': chat.sender_id,
#                             'message': message.sender_ciphertext
#                         }
#                     else:
#                         dict_chat_user = {
#                             'id': chat_user.id,
#                             'username': chat_user.username,
#                             'public_key': chat_user.public_key,
#                             'last_message_id': message2.id,
#                             'sender_id': chat2.sender_id,
#                             'message': message2.sender_ciphertext
#                         }
                    
#                     list_chatted_user.append(dict_chat_user)
#             else:
#                 if chat.sender_id in [user['id'] for user in list_chatted_user]:
#                     continue
#                 else:
#                     chat2 = db.session.query(ChattedUser).filter(ChattedUser.recipient_id == chat.sender_id, ChattedUser.sender_id == chat.recipient_id).first()
#                     chat_user = User.query.filter_by(id=chat.sender_id).first()
                    
#                     message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc().desc()).first()
#                     message2 = Messages.query.filter_by(chatted_id=chat2.id).order_by(Messages.timestamp.desc().desc()).first()
                    
#                     if message.timestamp >= message2.timestamp:
#                         dict_chat_user = {
#                             'id': chat_user.id,
#                             'username': chat_user.username,
#                             'public_key': chat_user.public_key,
#                             'last_message_id': message.id,
#                             'sender_id': chat.sender_id,
#                             'message': message.sender_ciphertext
#                         }
#                     else:
#                         dict_chat_user = {
#                             'id': chat_user.id,
#                             'username': chat_user.username,
#                             'public_key': chat_user.public_key,
#                             'last_message_id': message2.id,
#                             'sender_id': chat2.sender_id,
#                             'message': message2.sender_ciphertext
#                         }
                   
#                     list_chatted_user.append(dict_chat_user)
#             print("LIST CHATTED USER: ", list_chatted_user)