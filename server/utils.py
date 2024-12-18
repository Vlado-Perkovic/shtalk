from config import clients,groups
import uuid


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
        message = message.get('message')
        timestamp = message.get('timestamp')
        sender = message.get('sender')
    except Exception as error:
        print(f"{error}")
    # Check if the target exists in clients
    if recipient not in clients:
        sender_writer = clients[sender]
        if sender_writer:
            error_msg = f"Error: User {recipient} not found.\n"
            sender_writer.write(error_msg.encode())
            await sender_writer.drain()
        print(f"[Error] User {recipient} not found when {sender} tried to send a message.")
        return
    
    # Send the message
    target_writer = clients[recipient]
    try:
        msg_to_send = f"Private message from {sender}: {message}\n"
        target_writer.write(msg_to_send.encode())
        await target_writer.drain()

        # Store message in database
        try:
            await store_message_single(sender=sender, recipient=recipient, content=message,timestamp=timestamp,group_name=None, db=database)
        except Exception as db_error:
            print(f"[Database Error] Failed to store message: {db_error}")
        
        print(f"Message sent from {sender} to {recipient}: {message}")

    except ConnectionResetError:
        print(f"[Connection Error] Failed to deliver message to {recipient} - Connection lost.")


async def send_group_message(message, database):
    try:
        content = message.get('message')
        timestamp = message.get('timestamp')
        sender = message.get('sender')
        group_name = message.get('group')
    except Exception as error:
        print(f"{error}")
    
    groups = await get_groups(database)

    if group_name not in groups:
        sender_writer = clients[sender]
        sender_writer.write(f"Group {group_name} does not exist or the sender has no permission to send".encode())
        await sender_writer.drain()
        return
    
    try:
        await store_message_group(sender=sender, content=content, timestamp=timestamp, group_name=group_name, db=database)
    except ConnectionResetError:
        print(f"Failed to deliver messages")




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
                    VALUES (?, ?, ?, ?, ?, ?, ?)
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
        async with database.execute("SELECT user_id FROM group_members WHERE group_name = ?", (group_name)) as cursor:
            async for row in cursor:
                members.append(row)
    except Exception as e:
            print(f"Error getting recipient ID: {e}")
            return
    
    return members


async def get_groups(database):
    groups = []
    try:
        async with database.execute("SELECT id FROM groups") as cursor:
            async for row in cursor:
                groups.append(row)
    except Exception as e:
            print(f"Error getting recipient ID: {e}")
            return
    
    return groups
