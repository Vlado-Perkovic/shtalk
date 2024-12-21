from config import clients, publicKeys
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
    try:
        target_writer = clients[recipient]
    except Exception as e:
        return {
                "type": "error",
                "message": f"Failed to deliver message to {recipient}. - Connection lost"
            }
    try:
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

        target_writer.write(msg_to_send.encode())
        await target_writer.drain()

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
    Sends a group message to a specific target client.
    """
    try:
        recipient = message.get('recipient')
        message_content = message.get('message')
        timestamp = message.get('timestamp')
        sender = message.get('sender')
        group_name = message.get('group_name')
    except Exception as error:
        print(f"[Parsing Error] {error}")
        return {"type": "error",
                "message": "Parsing error."
                }
    
    groups = await get_groups(database)

    if group_name not in groups:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] Group {group_name} not found or sender {sender} lacks permissions.")
            return {
                "type": "error",
                "message": f"Group {group_name} does not exist or sender has no permission."
            }
        
    user_group_ids = await get_users_in_group(group_name, database)

    try:
        async with database.execute("SELECT user_id FROM users WHERE username = ?", (sender,)) as cursor:
            row = await cursor.fetchone()
            if row:
                user_id_sender = row[0]
                
            else:
                print(f"User {recipient} not found")
    except Exception as e:
        print(f"Error getting sender ID: {e}")
        return {
                "type": "error",
                "message": f"Sender {sender} does not exist or has no permission."
            }
    
    if user_id_sender not in user_group_ids:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] Sender {sender} not found or sender {sender} lacks permissions.")
            return {
                "type": "error",
                "message": f"Sender {sender} does not exist or has no permission."
            }
    
    try:
        async with database.execute("SELECT user_id FROM users WHERE username = ?", (recipient,)) as cursor:
            row = await cursor.fetchone()
            if row:
                user_id_recipient = row[0]
                
            else:
                print(f"User {recipient} not found")
    except Exception as e:
        print(f"Error getting sender ID: {e}")
        return {
                "type": "error",
                "message": f"Recipient {recipient} does not exist or sender has no permission."
            }
    
    
    if user_id_recipient not in user_group_ids:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] Recipient  {recipient} not found or sender {sender} lacks permissions.")
            return {
                "type": "error",
                "message": f"Recipient {recipient} does not exist or sender has no permission."
            }
        
    if recipient not in clients:
        sender_writer = clients.get(sender)
        if sender_writer:
            print(f"[Error] User {recipient} not found when {sender} tried to send a message.")
            return {"type": "error",
                "message": f"User {recipient} not found."
                }
    try:
        target_writer = clients[recipient]
    except Exception as e:
        return {
                "type": "error",
                "message": f"Failed to deliver message to {recipient}. - Connection lost"
            }
    try:
        msg_to_send = json.dumps({
                    "type": "group",
                    "sender": sender,
                    "group_name": group_name,
                    "recipient": recipient,
                    "timestamp": timestamp,
                    "message": {
                        "ciphertext": message_content.get('ciphertext'),
                        "iv": message_content.get('iv'),
                        "signature": message_content.get('signature')
                    }
        })

        target_writer.write(msg_to_send.encode())
        await target_writer.drain()

        try:
            await store_message_single(
                sender=sender,
                recipient=recipient,
                content=message_content,
                timestamp=timestamp,
                group_name=group_name,
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


async def store_message_single(sender, recipient, content, timestamp, group_name, db):

    try:
        sender_id = None
        recipient_id = None
        try:
            async with db.execute("SELECT user_id FROM users WHERE username = ?", (sender,)) as cursor:
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
            async with db.execute("SELECT user_id FROM users WHERE username = ?", (recipient,)) as cursor:
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
        if group_name == None:
            await db.execute(
                    """
                    INSERT INTO messages (message_id, sender_id, recipient_id, ciphertext, iv, signature, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (message_id, sender_id, recipient_id, ciphertext, iv, signature, timestamp)
                )
        else:
            await db.execute(
                    """
                    INSERT INTO messages (message_id, sender_id, recipient_id,group_name, ciphertext, iv, signature, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (message_id, sender_id, recipient_id,group_name, ciphertext, iv, signature, timestamp)
                )
        await db.commit()
        print("Message stored successfully")

    except Exception as e:
        print(f"Error storing message: {e}")

async def return_public_key(usernames):
    keys = dict()
    for username in usernames:
        if username in publicKeys.keys():
            keys[username] = publicKeys[username]
    if len(keys.keys()) == 0:
        return {
            "type" : "error",
            "message" : "No keys found for given usernames"
        }
    return {
        "type" : "success",
        "keys" : keys
    }

async def get_users_in_group(group_name, database):
    members = []
    
    try:
        async with database.execute("SELECT user_id FROM group_members WHERE group_name = ?", (group_name,)) as cursor:
            async for row in cursor:
                members.append(row[0])
    except Exception as e:
        print(f"Error getting recipient ID: {e}")
        return
    
    return members


async def create_group(usernames, group_name, description, database):
    async with database.execute(
        "SELECT * FROM groups WHERE group_name = :group_name",
        {"group_name": group_name}
    ) as cursor:
        existing_group = await cursor.fetchone()

    if existing_group:
        return {"type":"error",
                "message": "Group already exists"}
    for username in usernames:
        async with database.execute(
            "SELECT user_id FROM users WHERE username = :username",
            {"username": username}
        ) as cursor:
            user_id = await cursor.fetchone()
        
        if not user_id:
            print( {"type":"error","message": "Username doesn't exist"})

    await database.execute(
        """
        INSERT INTO groups (group_name, description) 
        VALUES (:group_name, :description)
        """,
        {"group_name": group_name, "description": description}
    )
    await database.commit()
    for username in usernames:
        response = await add_user_to_group(group_name, username, database)
        print(response)

    return {"type":"success",
            "message": f"Group '{group_name}' created"}


async def add_user_to_group(group_name, username, database):
    async with database.execute(
        "SELECT user_id FROM users WHERE username = :username",
        {"username": username}
    ) as cursor:
        user_id_row = await cursor.fetchone()
    
    if not user_id_row:
        return {"type":"error", "message": "Username doesn't exist"}

    user_id = user_id_row[0]
    
    async with database.execute(
        "SELECT * FROM group_members WHERE group_name = :group_name AND user_id = :user_id",
        {"group_name": group_name, "user_id": user_id}
    ) as cursor:
        existing_member = await cursor.fetchone()
    
    if existing_member:
        return {"type":"error", "message": "User is already a member of the group"}

    await database.execute(
        """
        INSERT INTO group_members (group_name, user_id, role)
        VALUES (:group_name, :user_id, :role)
        """,
        {"group_name": group_name, "user_id": user_id, "role": 'member'}
    )
    await database.commit()
    
    return {"type":"success", "message": f"User {username} added to group {group_name}"}

async def login_user(username, password, database):

    async with database.execute(
        "SELECT * FROM users WHERE username = ?", 
        (username,)
    ) as cursor:
        user = await cursor.fetchone()
        print(user)

    if not user:
        return {"type":"error", "message": "Invalid username or password"}

    if password != user[3]:
        return {"type":"error", "message": "Invalid username or password"}

    if user[5] == 0:
        return {"type":"error", "message": "Email not verified"}

    token = jwt.encode(
        {
            "user_id": user[6],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        JWT_SECRET,
        algorithm="HS256"
    )

    return {"type":"success", "message": f"User {username} logged in", "token": token}

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
    await database.commit()

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
        return {"type": "error", "message": f"Invalid email: {str(e)}"}

    async with database.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?", 
        (username, email)
    ) as cursor:
        user_exists = await cursor.fetchone()

    if user_exists:
        return {"type": "error", "message": "Username or email already exists"}

    verification_token = secrets.token_urlsafe(16)

    await database.execute(
        """
        INSERT INTO users (username, email, password_hash, verification_token, is_verified)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, password, verification_token, 1)
    )

    await database.commit()

    print(f"Verification token for {email}: {verification_token}")

    return {"type": "success", "message": "User registered successfully"}


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
