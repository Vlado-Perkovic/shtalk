import asyncio
import json
import aiosqlite
import bcrypt
import secrets
from email_validator import validate_email, EmailNotValidError
import jwt
from datetime import datetime, timedelta
import pyotp

JWT_SECRET = "jwt_secret_from_env"
HOST = '127.0.0.1'
PORT = 8888
clients = {}
groups = {
    'group1': []
}

def setup_mfa():
    """
    Generates and returns a TOTP secret for a user.
    """
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    print(f"Scan this QR Code with an authenticator app: {totp.provisioning_uri('user@example.com', issuer_name='SecureChat')}")
    return secret

def verify_mfa(secret, code):
    """
    Verifies the TOTP code provided by the user.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

async def login_user(username, password, mfa_code, database):
    """
    Authenticates a user and issues a JWT token, after verifying MFA.
    """
    user = await database.fetch_one(
        "SELECT * FROM users WHERE username = :username", {"username": username}
    )
    if not user:
        return {"error": "Invalid username or password"}

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return {"error": "Invalid username or password"}

    if not user["is_verified"]:
        return {"error": "Email not verified"}

    # Verify MFA
    if not verify_mfa(user["mfa_secret"], mfa_code):
        return {"error": "Invalid MFA code"}

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"token": token}



async def register_user(username, email, password, database):
    """
    Registers a new user
    """
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return {"error": f"Invalid email: {str(e)}"}

    user_exists = await database.fetch_one(
        "SELECT * FROM users WHERE username = :username OR email = :email",
        {"username": username, "email": email}
    )
    if user_exists:
        return {"error": "Username or email already exists"}

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    verification_token = secrets.token_urlsafe(16)

    await database.execute(
        """
        INSERT INTO users (username, email, password_hash, verification_token)
        VALUES (:username, :email, :password_hash, :verification_token)
        """,
        {
            "username": username,
            "email": email,
            "password_hash": password_hash.decode(),
            "verification_token": verification_token,
        }
    )

    print(f"Verification token for {email}: {verification_token}")
    return {"success": "User registered successfully"}


async def handle_client(reader, writer):
    """
    Function to handle clients
    """
    address = writer.get_extra_info('peername')
    print(f"New connection from {address}")
    clients[address] = writer

    database = await aiosqlite.connect("/chatroom.db")
    try:
        while True:
            data = await reader.readline()
            if not data:
                print(f"Client {address} disconnected")
                break
            
            # Deserialize incoming message
            try:
                message = json.loads(data.decode().strip())
            except json.JSONDecodeError:
                writer.write("Invalid message format".encode())
                await writer.drain()
                continue
            
            print(f"Received from {address}: {message}")
            
            # Handle login
            if message.get('type') == 'login':
                response = await login_user(message['username'], message['password'], database)
                writer.write(json.dumps(response).encode())
                await writer.drain()
            
            # Handle registration
            elif message.get('type') == 'register':
                response = await register_user(message['username'], message['email'], message['password'], database)
                writer.write(json.dumps(response).encode())
                await writer.drain()
            
            # Handle private message
            elif message.get('type') == 'private':
                await send_private_message(message, address,database)
            
            # Handle group message
            elif message.get('type') == 'group':
                await send_group_message(message, address,database)
            
            else:
                writer.write("Unknown message type".encode())
                await writer.drain()

    except ConnectionResetError:
        print(f"Connection lost with {address}")
    
    del clients[address]
    writer.close()
    await writer.wait_closed()
    print(f"Connection closed with {address}")

async def send_private_message(message, sender_address,database):
    """
    Sends a private message to a specific target client.
    """
    target = message.get('target')
    content = message.get('content')

    for address, writer in clients.items():
        if address[0] == target[0] and address[1] == target[1]:
            try:
                writer.write(f"Private message from {sender_address}: {content}\n".encode())
                await writer.drain()
                await store_message(sender=sender_address,recipient=address,content=content,db=database)
                return
            except ConnectionResetError:
                print(f"Failed to deliver message to {address}")

    sender_writer = clients[sender_address]
    sender_writer.write(f"User {target} not found\n".encode())
    await sender_writer.drain()

async def send_group_message(message, sender_address, database):
    """
    Sends a message to a group from a group member
    """
    group_name = message.get('target')
    content = message.get('content')
    
    if group_name not in groups:
        sender_writer = clients[sender_address]
        sender_writer.write(f"Group {group_name} does not exist or the sender has no permission to send".encode())
        await sender_writer.drain()
        return
    
    if sender_address not in groups[group_name]:
        sender_writer = clients[sender_address]
        sender_writer.write(f"Group {group_name} does not exist or the sender has no permission to send".encode())
        await sender_writer.drain()
        return

    for address in groups[group_name]:
        if address != sender_address:  # Don't send to the sender
            try:
                writer = clients[address]
                writer.write(f"Group message from {sender_address}: {content}".encode())
                await writer.drain()
                await store_message(sender=sender_address,recipient=address,content=content,db=database)
            except ConnectionResetError:
                print(f"Failed to deliver message to {address}")

async def store_message(sender, recipient, content, db):
    try:
        await db.execute(
            "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
            (sender, recipient, content)
        )
        await db.commit()
        print("Message stored into database")
    except Exception as e:
        print(f"Error storing message: {e}")

async def main():
    """
    Main function
    """
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Server started on {HOST}:{PORT}")
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
