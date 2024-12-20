from config import clients
import uuid
import json
import secrets
from email_validator import validate_email, EmailNotValidError
import jwt
from datetime import datetime, timedelta
from config import clients, JWT_SECRET


async def read_all_clients(database) -> dict:
    """
    Reads all clients from the 'users' table and stores them in a dictionary.
    """
    clients = {}

    try:
        async with database.execute(
            "SELECT id, username, email, is_verified FROM users"
        ) as cursor:
            async for row in cursor:
                user_id, username, email, is_verified = row
                clients[user_id] = {
                    "username": username,
                    "email": email,
                    "is_verified": bool(is_verified)
                }

        return clients

    except Exception as e:
        print(f"Error reading clients: {e}")
        return {}

async def send_private_message(message, database):
    """
    Sends a private message to a specific target client.
    """
    try:
        recipient = message.get('recipient')
        message_content = message.get('message')
        timestamp = message.get('timestamp')
        sender = message.get('sender')
    except Exception as error:
        print(f"[Parsing Error] {error}")
        return {"type": "error",
                "message": "Parsing error."
                }
 
    if recipient not in clients:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] User {recipient} not found when {sender} tried to send a message.")
            return {"type": "error",
                "message": f"User {recipient} not found."
                }
    
    # Send the message
    target_writer = clients[recipient]
    try:
        # Create JSON message
        msg_to_send = json.dumps({
            "type": "private",
            "sender": sender,
            "recipient": recipient,
            "timestamp": timestamp,
            "message": {
                "ciphertext": message_content.get('ciphertext'),
                "iv": message_content.get('iv'),
                "signature": message_content.get('signature'),
                "key": message_content.get('key')
            }
        })

        # Send the message to the recipient
        target_writer.write(msg_to_send.encode())
        await target_writer.drain()

        # Store message in the database
        try:
            await store_message_single(
                sender=sender,
                recipient=recipient,
                content=message_content,
                timestamp=timestamp,
                db=database
            )
        except Exception as db_error:
            print(f"[Database Error] Failed to store message: {db_error}")

        print(f"Message sent from {sender} to {recipient}: {message_content}")

    except ConnectionResetError:
        print(f"[Connection Error] Failed to deliver message to {recipient} - Connection lost.")
        return {
                "type": "error",
                "message": f"Failed to deliver message to {recipient}. - Connection lost"
            }

    return {
                "type": "success",
                "message": f"Sent to {recipient}."
            }

async def send_group_message(message, database):
    """
    Sends a group message to all members of a specified group.
    """
    try:
        message_content = message.get('message')
        timestamp = message.get('timestamp')
        sender = message.get('sender')
        group_name = message.get('group_name')
    except Exception as error:
        print(f"[Parsing Error] {error}")
        return {"type": "error",
                "message": "Parsing error."
                }

    # Check if the group exists
    groups = await get_groups(database)

    if group_name not in groups:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] Group {group_name} not found or sender {sender} lacks permissions.")
            return {
                "type": "ERROR",
                "message": f"Group {group_name} does not exist or sender has no permission."
            }
    
    # Retrieve users in the group
    user_group = await get_users_in_group(group_name, database)


    if sender not in user_group:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] Group {group_name} not found or sender {sender} lacks permissions.")
            return {
                "type": "ERROR",
                "message": f"Group {group_name} does not exist or sender has no permission."
            }

    # Send message to all users in the group
    for user in user_group:
        if user in clients.keys:
            target_writer = clients[user]
            try:
                # Create JSON message
                msg_to_send = json.dumps({
                    "type": "GROUP",
                    "sender": sender,
                    "group_name": group_name,
                    "timestamp": timestamp,
                    "message": {
                        "ciphertext": message_content.get('ciphertext'),
                        "iv": message_content.get('iv'),
                        "signature": message_content.get('signature'),
                        "key": message_content.get('key')
                    }
                })

                target_writer.write(msg_to_send.encode())
                await target_writer.drain()

            except ConnectionResetError:
                print(f"[Connection Error] Failed to deliver message to {user} - User offline.")
    
    # Store the message in the database
    try:
        await store_message_group(
            sender=sender, 
            content=message_content, 
            timestamp=timestamp, 
            group_name=group_name, 
            db=database
        )
        print(f"Message from {sender} sent to group {group_name}: {message_content}")
        
    except Exception as db_error:
        print(f"[Database Error] Failed to store message: {db_error}")

    return {
                "type": "success",
                "message": f"Sent to {group_name}."
            }


async def store_message_single(sender, recipient, content, timestamp, db):
    
    try:
        sender_id = None
        recipient_id = None
        try:
            async with db.execute("SELECT id FROM users WHERE username = ?", (sender,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    sender_id = row[0]
                else:
                    print(f"Sender {sender} not found")
                    return
        except Exception as e:
            print(f"Error getting sender ID: {e}")
            return

        try:
            async with db.execute("SELECT id FROM users WHERE username = ?", (recipient,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    recipient_id = row[0]
                else:
                    print(f"Recipient {recipient} not found")
                    return
        except Exception as e:
            print(f"Error getting recipient ID: {e}")
            return

        ciphertext = content.get('ciphertext')
        iv = content.get('iv')
        signature = content.get('signature')

        message_id = str(uuid.uuid4())

        await db.execute(
                """
                INSERT INTO messages (message_id, sender_id, recipient_id, ciphertext, iv, signature, sent_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (message_id, sender_id, recipient_id, ciphertext, iv, signature, timestamp)
            )
        await db.commit()
        print("Message stored successfully")

    except Exception as e:
        print(f"Error storing message: {e}")



async def store_message_group(sender, content, timestamp, group_name, db):
    
    try:
        sender_id = None
        try:
            async with db.execute("SELECT id FROM users WHERE username = ?", (sender,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    sender_id = row[0]
                else:
                    print(f"Sender {sender} not found")
                    return
        except Exception as e:
            print(f"Error getting sender ID: {e}")
            return

        members = await get_users_in_group(group_name, db)

        if sender_id not in members:
            return
        
        ciphertext = content.get('ciphertext')
        iv = content.get('iv')
        signature = content.get('signature')
        
        for recipient_id in members:
            message_id = str(uuid.uuid4())
            await db.execute(
                    """
                    INSERT INTO messages (message_id, sender_id, recipient_id,group_name,ciphertext, iv, signature, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?,?)
                    """,
                    (message_id, sender_id, recipient_id, group_name, ciphertext, iv, signature, timestamp)
                )
        await db.commit()
        print("Message stored successfully")

    except Exception as e:
        print(f"Error storing message: {e}")


async def get_users_in_group(group_name, database):
    members = []
    
    try:
        # Pass group_name as a tuple with one element
        async with database.execute("SELECT username FROM group_members WHERE group_name = ?", (group_name,)) as cursor:
            async for row in cursor:
                members.append(row[0])
    except Exception as e:
        print(f"Error getting recipient ID: {e}")
        return
    
    return members


async def create_group(username, group_name, description, database):
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

    user_id = await database.fetch_one(
        "SELECT user_id FROM groups WHERE username = :username",
        {"username": username}
    )

    # Add the user as the first member (admin) of the group
    await add_user_to_group(group_name, user_id, database)

    return {"type":"success",
            "message": f"Group '{group_name}' created"}

async def add_user_to_group(group_name, username, database):

    user_id = await database.fetch_one(
        "SELECT user_id FROM groups WHERE username = :username",
        {"username": username}
    )

    if not user_id:
        return {"type":"error",
                "message": "Username doesn't exist"}

    # Check if the user is already in the group
    existing_member = await database.fetch_one(
        "SELECT * FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )
    
    if existing_member:
        return {"type":"error",
                "message": "User is already a member of the group"}

    # Add user to group
    await database.execute(
        """
        INSERT INTO group_members (group_name, user_id)
        VALUES (:group_name, :user_id, :role)
        """,
        {"group_name": group_name, "user_id": user_id, "role": 'member'}
    )
    
    return {"type":"success",
            "message": f"User {user_id} added to group {group_name}"}

async def login_user(username, password, database):

    user = await database.fetch_one(
        "SELECT * FROM users WHERE username = :username", {"username": username}
    )

    if not user:
        return {"type":"error",
                "message": "Invalid username or password"}

    if password.encode() != user["password_hash"].encode():
        return {"type":"error",
                "message": "Invalid username or password"}

    if not user["is_verified"]:
        return {"type":"error",
                "message": "Email not verified"}

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    
    return {"type":"success",
            "message": f"User {username} logged in"}

async def leave_group(user_id, group_name, database):

    member = await database.fetch_one(
        "SELECT * FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )

    if not member:
        return {"type":"error",
                "message": "User is not a member of the group"}
        

    await database.execute(
        "DELETE FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    )

    return {"type":"success",
            "message":f"User {user_id} has left the group '{group_name}'"}



async def get_groups(database):
    groups = []
    try:
        async with database.execute("SELECT group_name FROM groups") as cursor:
            async for row in cursor:
                groups.append(row[0])
    except Exception as e:
            print(f"Error getting recipient ID: {e}")
            return groups
    
    return groups

async def register_user(username, email, password, database):
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return {"type":"error",
                "message": f"Invalid email: {str(e)}"}

    user_exists = await database.fetch_one(
        "SELECT * FROM users WHERE username = :username OR email = :email",
        {"username": username, "email": email}
    )
    if user_exists:
        return {"type":"error",
                "message": "Username or email already exists"}

    verification_token = secrets.token_urlsafe(16)

    await database.execute(
        """
        INSERT INTO users (username, email, password_hash, verification_token)
        VALUES (:username, :email, :password_hash, :verification_token)
        """,
        {
            "username": username,
            "email": email,
            "password_hash": password.decode(),
            "verification_token": verification_token,
            "is_verified": 1
        }
    )
    #Check what to do with is_verified and verification token- if we have time
    print(f"Verification token for {email}: {verification_token}")

    return {"type":"success",
            "message":"User registered successfully"}


async def fetch_history(user_id, target, target_type, database, limit=50, offset=0):
    """
    Fetch chat history between a user and a target (either another user or a group).

    :param user_id: ID of the requesting user
    :param target_id: ID of the target user or group
    :param target_type: 'private' or 'group'
    :param database: Database connection
    :param limit: Maximum number of messages to return
    :param offset: Number of messages to skip (for pagination)
    :return: List of messages or an error message
    """
    messages = []
    query = ""
    params = {}

    try:
        if target_type == 'private':
            query = (
                "SELECT sender_id, recipient_id, ciphertext, iv, signature, sent_at "
                "FROM messages WHERE (sender_id = :user_id AND recipient_id = :target_id) "
                "OR (sender_id = :target_id AND recipient_id = :user_id) "
                "ORDER BY sent_at DESC LIMIT :limit OFFSET :offset"
            )
            params = {
                "user_id": user_id, "target_id": target, "limit": limit, "offset": offset
            }

        elif target_type == 'group':
            query = (
                "SELECT sender_id, group_name, ciphertext, iv, signature, sent_at "
                "FROM messages WHERE group_name = :target_id "
                "ORDER BY sent_at DESC LIMIT :limit OFFSET :offset"
            )
            params = {
                "target_id": target, "limit": limit, "offset": offset
            }

        async with database.execute(query, params) as cursor:
            async for row in cursor:
                messages.append({
                    "sender_id": row[0],
                    "recipient_id": row[1] if target_type == 'private' else None,
                    "ciphertext": row[2],
                    "iv": row[3],
                    "signature": row[4],
                    "sent_at": row[5]
                })

        return messages

    except Exception as e:
        return {"type":"error",
                "message": f"Failed to fetch chat history: {str(e)}"}
