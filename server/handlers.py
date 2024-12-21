import json
import aiosqlite
from config import clients,publicKeys
import utils


async def handle_client(reader, writer):
    """
    Function to handle clients
    """
    address = writer.get_extra_info('peername')
    print(f"New connection from {address}")
    
    database = await aiosqlite.connect("chatroom.db")
    loggedIn = False
    try:
        while True:
            data = await reader.readline()
            if not data:
                print(f"Client {address} disconnected")
                break
            # Deserialize incoming message
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                writer.write("Invalid message format".encode())
                await writer.drain()
                continue
            
            print(f"Received from {address}: {message}")
            
            if message.get('type') == 'login':
                response = await utils.login_user(message['username'], message['password'], database)
                try:
                    writer.write(json.dumps(response).encode())
                    await writer.drain()
                    if response['type'] == 'success':
                        loggedIn = True
                        clients[message['username']] = writer
                        publicKeys[message['username']] = message['public_key']
                except Exception as e:
                    print(f"Error while sending response: {e}")
            elif message.get('type') == 'log_out' and loggedIn:
                username = message['username']
                response = {
                    'type':'success',
                    'message' : 'Logged out successfully'
                }
                try:
                    loggedIn = False
                    clients.pop(username)
                    publicKeys.pop(username)
                except:
                    response = {
                        'type':'error',
                        'message' : 'Logged out failed'
                }
                writer.write(json.dumps(response).encode())
                await writer.drain()
            elif message.get('type') == 'register':
                response = await utils.register_user(message['username'], message['email'], message['password'], database)
                print(response)
                writer.write(json.dumps(response).encode())
                await writer.drain()
            elif message.get('type') == 'private' and loggedIn:
                response =  await utils.send_private_message(message,database)
                writer.write(json.dumps(response).encode() + b'\n')
                print(response)
                await writer.drain()
            elif message.get('type') == 'group' and loggedIn:
                response = await utils.send_group_message(message,database)
                writer.write(json.dumps(response).encode())
                print(response)
                await writer.drain()
            elif message.get('type') == 'new_group' and loggedIn:
                response = await utils.create_group(message['usernames'],message['group_name'],message['description'],database)
                writer.write(json.dumps(response).encode())
                print(response)
                await writer.drain()
            elif message.get('type') == 'add' and loggedIn:
                response = await utils.add_user_to_group(message['group_name'],message['username'],database)
                writer.write(json.dumps(response).encode())
                print(response)
                await writer.drain()
            elif message.get('type') == 'history' and loggedIn:
                response = await handle_history_request(message,writer,database)
                writer.write(json.dumps(response).encode())
                print(response)
                await writer.drain()
            elif message.get('type') == 'get_keys' and loggedIn:
                response = await utils.return_public_key(message['usernames'])
                writer.write(json.dumps(response).encode())
                print(response)
                await writer.drain()
            else:
                writer.write("Unknown message type".encode())
                print(response)
                await writer.drain()

    except ConnectionResetError:
        print(f"Connection lost with {address}")
    
    writer.close()
    await writer.wait_closed()
    print(f"Connection closed with {address}")


async def handle_history_request(message, writer, database):
    """
    Handle client requests to retrieve chat history.

    :param message: Incoming message from client
    :param writer: Stream writer to send the response back
    :param database: Database connection
    """
    user_id = message.get('user_id')
    target_id = message.get('target_id')
    target_type = message.get('target_type')
    limit = message.get('limit', 50)
    offset = message.get('offset', 0)

    if not user_id or not target_id or not target_type:
        response = {"error": "Missing required parameters"}
        writer.write(json.dumps(response).encode())
        await writer.drain()
        return

    history = await utils.fetch_history(user_id, target_id, target_type, database, limit, offset)
    response = {"history": history} if isinstance(history, list) else history

    writer.write(json.dumps(response).encode())
    await writer.drain()