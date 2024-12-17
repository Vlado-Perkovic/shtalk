import json
import aiosqlite
import bcrypt
import secrets
from email_validator import validate_email, EmailNotValidError
import jwt
from datetime import datetime, timedelta
from config import clients, JWT_SECRET
import handlers as h

# Add your functions here from the original script

async def create_group(user_id, group_name, description, database):
    # Check if the group already exists
    existing_group = await database.fetch_one(
        "SELECT * FROM groups WHERE group_name = :group_name",
        {"group_name": group_name}
    )

    if existing_group:
        return {"error": "Group already exists"}

    # Insert the group into the database
    await database.execute(
        """
        INSERT INTO groups (group_name, description) 
        VALUES (:group_name, :description)
        """,
        {"group_name": group_name, "description": description}
    )

    # Add the user as the first member (admin) of the group
    await add_user_to_group(group_name, user_id,database)

    return {"success": f"Group '{group_name}' created"}


async def add_user_to_group(group_name, user_id, database):
    # Check if the user is already in the group
    existing_member = await database.fetch_one(
        "SELECT * FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )
    
    if existing_member:
        return {"error": "User is already a member of the group"}

    # Add user to group
    await database.execute(
        """
        INSERT INTO group_members (group_name, user_id)
        VALUES (:group_name, :user_id, :role)
        """,
        {"group_name": group_name, "user_id": user_id}
    )
    
    return {"success": f"User {user_id} added to group {group_name}"}


async def login_user(username, password, database):
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

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"token": token}


async def leave_group(user_id, group_name, database):
    # Check if the user is in the group
    member = await database.fetch_one(
        "SELECT * FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )

    if not member:
        return {"error": "User is not a member of the group"}

    # Remove the user from the group
    await database.execute(
        "DELETE FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )

    return {"success": f"User {user_id} has left the group '{group_name}'"}


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
                await h.send_private_message(message, address,database)
            
            # Handle group message
            elif message.get('type') == 'group':
                await h.send_group_message(message, address,database)
            
            else:
                writer.write("Unknown message type".encode())
                await writer.drain()

    except ConnectionResetError:
        print(f"Connection lost with {address}")
    
    del clients[address]
    writer.close()
    await writer.wait_closed()
    print(f"Connection closed with {address}")