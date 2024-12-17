from config import clients,groups


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
