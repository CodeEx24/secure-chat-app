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


# MAIN CONNECT PREVIOUS
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    list_chatted_user = []
    if user:
        chatted_user = ChattedUser.query.filter(
            or_(
                ChattedUser.sender_id == user_id,
                ChattedUser.recipient_id == user_id
            )
        ).all()
        
        
        if chatted_user:
            for chat in chatted_user:
                print("CHAT ID: ", chat.id)
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
                        
                        # Check if chat_user.id is highest to user_id
                        if chat_user and (chat_user.id > user_id):
                            # Join room for lowest number - highest number
                            room = f'{user_id}-{chat_user.id}'
                            join_room(room)
                        else:
                            # Join room for highest number - lowest number
                            room = f'{chat_user.id}-{user_id}'
                            join_room(room)
                            

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
                                    'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
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
                                    'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
                                }
                        else:
                            print("ELSE WITHOUT CHAT 2")
                            dict_chat_user = {
                                'id': chat_user.id,
                                'username': chat_user.username,
                                'public_key': chat_user.public_key,
                                'last_message_id': message.id,
                                'sender_id': chat.sender_id,
                                'timestamp': message.timestamp.isoformat(), 
                                'message': message.sender_ciphertext if chat.sender_id == user.id else message.receiver_ciphertext,
                                'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
                                
                            }
                           
                        list_chatted_user.append(dict_chat_user)
                else:
                    if chat.recipient_id == user_id:
                        if chat.sender_id in [user['id'] for user in list_chatted_user]:
                            continue
                        else:
                            chat2 = ChattedUser.query.filter(
                                ChattedUser.sender_id == chat.recipient_id,
                                ChattedUser.recipient_id == chat.sender_id
                            ).first()
                            chat_user = User.query.get(chat.sender_id)
                            message = Messages.query.filter_by(chatted_id=chat.id).order_by(Messages.timestamp.desc()).first()
                            
                            # Check if chat_user.id is highest to user_id
                            if chat_user and (chat_user.id > user_id):
                                # Join room for lowest number - highest number
                                room = f'{user_id}-{chat_user.id}'
                                join_room(room)
                            else:
                                # Join room for highest number - lowest number
                                room = f'{chat_user.id}-{user_id}'
                                join_room(room)
                                

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
                                        'message': message.receiver_ciphertext if chat.recipient_id == user.id else message.sender_ciphertext,
                                        'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
                                    }
                                else:
                                    dict_chat_user = {
                                        'id': chat_user.id,
                                        'username': chat_user.username,
                                        'public_key': chat_user.public_key,
                                        'last_message_id': message2.id,
                                        'sender_id': chat2.sender_id,
                                        'timestamp': message2.timestamp.isoformat(), 
                                        'message': message2.receiver_ciphertext  if chat2.recipient_id == user.id else message2.sender_ciphertext,
                                        'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
                                    }
                            else:
                                print("ELSE WITHOUT CHAT 2")
                                dict_chat_user = {
                                    'id': chat_user.id,
                                    'username': chat_user.username,
                                    'public_key': chat_user.public_key,
                                    'last_message_id': message.id,
                                    'sender_id': chat.sender_id,
                                    'timestamp': message.timestamp.isoformat(), 
                                    'message': message.receiver_ciphertext  if chat.recipient_id == user.id else message.sender_ciphertext,
                                    'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
                                    
                                }
                            
                            list_chatted_user.append(dict_chat_user)
            print('list_chatted_user: ', list_chatted_user)
            # Sort the list based on the timestamp in descending order
            sort_chatted_user = sorted(list_chatted_user, key=lambda x: x['timestamp'], reverse=True)
            emit('chat_details', {'chat_user': sort_chatted_user, 'user_id': user_id, 'name': user.name, 'email': user.email, 'username': user.username})
        else:
            print("THERES NO CURRENT CHAT")



# Send the new message here
@socketio.on('chat_history')
def get_chat_history(data):
    user_id = session.get('user_id')
    chat_user_id = data['chat_user_id']
   
    user = User.query.get(user_id)
    
    if chat_user_id:
        current_chat_user = User.query.get(chat_user_id)
        
        if user and current_chat_user:
            room = f'{min(user.id, current_chat_user.id)}-{max(user.id, current_chat_user.id)}'
            join_room(room)
            current_chat_public_key = current_chat_user.public_key
            chat_history, total_message_count, render_message_count = retrieve_chat_history(user.id, current_chat_user.id, 0, True)
    
            emit('detailed_chat_user_info', {
                'current_chat_public_key': current_chat_public_key,
                'current_chat_username': current_chat_user.username,
                'chat_history': chat_history,
                'total_message_count': total_message_count,
                'render_message_count': render_message_count,
                'chat_user_photo': 'https://img.freepik.com/free-psd/3d-illustration-person-with-sunglasses_23-2149436188.jpg?w=826&t=st=1698739208~exp=1698739808~hmac=9df91192abe8f8c2ad07c446f939ed2b08e2dd7561df3636aba7bc8df7447fe3'
            })
          

# Send the new message here
@socketio.on('load_more_message')
def get_chat_history(data):
    user_id = session.get('user_id')
    chat_user_id = data['chat_user_id']
    rendered_message = data['rendered_message']
   
    user = User.query.get(user_id)
    
    if chat_user_id:
        current_chat_user = User.query.get(chat_user_id)
        
        if user and current_chat_user:
            chat_history, total_message_count, render_message_count = retrieve_chat_history(user.id, current_chat_user.id, rendered_message)
                        
            if chat_history:
                emit('load_messages', {
                    'chat_history': chat_history,
                    'total_message_count': total_message_count,
                    'render_message_count': render_message_count
                })
            


# Send the new message here
@socketio.on('send_message')
def handle_new_message(data):
    user_id = session.get('user_id')  # Get the session user id
    # Get the message and recipient username
    chat_user_id = data.get('userReceiverId')
    sender_encrypted_message = data.get('senderEncryptedMessage')
    receiver_encrypted_message = data.get('receiverEncryptedMessage')
    
    # Get the user object from the database
    user =  User.query.filter_by(id=user_id).first()
    chat_user =  User.query.filter_by(id=chat_user_id).first()
    
    
    if user and chat_user:
        if user.id < chat_user.id:
            room = f'{user.id}-{chat_user.id}'
        else:
            room = f'{chat_user.id}-{user.id}'
        
        # Check if a chat user already exists
        chatted_user = ChattedUser.query.filter_by(sender_id=user.id, recipient_id=chat_user.id).first()
        current_time = datetime.now()

        # If chatted user exist save the message in database
        if chatted_user:
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, sender_ciphertext=sender_encrypted_message, receiver_ciphertext=receiver_encrypted_message)
            db.session.add(messageDetails)
            db.session.commit()  # Commi
            emit('message', {'sender': user_id, 'receiver': chatted_user.recipient_id, 'senderCipher': messageDetails.sender_ciphertext, 'receiverCipher': messageDetails.receiver_ciphertext}, room=room)
    
        else:
            # Create a chatted user
            create_chat_user = ChattedUser(sender_id=user.id, recipient_id=chat_user.id)
            db.session.add(create_chat_user)
            db.session.commit()
            
            chatted_user = ChattedUser.query.filter_by(sender_id=user.id, recipient_id=chat_user.id).first()
            messageDetails = Messages(chatted_id=chatted_user.id, timestamp=current_time, sender_ciphertext=sender_encrypted_message, receiver_ciphertext=receiver_encrypted_message)
            db.session.add(messageDetails)
            db.session.commit()
        
            emit('message', {'sender': user_id, 'receiver': chatted_user.recipient_id, 'senderCipher': messageDetails.sender_ciphertext, 'receiverCipher': messageDetails.receiver_ciphertext, 'new_message': True}, room=room)
   
           
        
        
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