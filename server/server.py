import asyncio
import json
import aiosqlite

HOST = '127.0.0.1'
PORT = 8888
clients = {}
groups = {
    'group1': []
}

async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    print(f"New connection from {address}")
    clients[address] = writer
    print(clients)
    
    try:
        while True:
            data = await reader.read(1024)
            if not data:
                print(f"Client {address} disconnected")
                break
             #JSON for now?
            try:
                message = json.loads(data.decode())
            except json.JSONDecodeError:
                writer.write("Invalid message format".encode())
                await writer.drain()
                continue
            print(f"Received from {address}: {message}")
        
            if message.get('type') == 'private':
                await send_private_message(message, address)
            elif message.get('type') == 'group':
                await send_group_message(message, address)
            else:
                writer.write("Unknown message type".encode())
                await writer.drain()

    except ConnectionResetError:
        print(f"Connection lost with {address}")
    
    del clients[address]
    writer.close()
    await writer.wait_closed()
    print(f"Connection closed with {address}")

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Server started on {HOST}:{PORT}")
    
    async with server:
        await server.serve_forever()


async def send_private_message(message, sender_address):
    target = message.get('target')
    content = message.get('content')

    for address, writer in clients.items():
        if str(address) == target:
            try:
                writer.write(f"Private message from {sender_address}: {content}".encode())
                await writer.drain()
                store_message(sender=sender_address,recipient=target,content=content)
                return
            except ConnectionResetError:
                print(f"Failed to deliver message to {address}")

    sender_writer = clients[sender_address]
    sender_writer.write(f"User {target} not found".encode())
    await sender_writer.drain()

async def send_group_message(message, sender_address):
    group_name = message.get('target')
    content = message.get('content')
    
    if group_name not in groups:
        sender_writer = clients[sender_address]
        sender_writer.write(f"Group {group_name} does not exist".encode())
        await sender_writer.drain()
        return

    for address in groups[group_name]:
        if address != sender_address:  # Don't send to the sender
            try:
                writer = clients[address]
                writer.write(f"Group message from {sender_address}: {content}".encode())
                await writer.drain()
                store_message(sender=sender_address,recipient=address,content=content)
            except ConnectionResetError:
                print(f"Failed to deliver message to {address}")

async def store_message(sender, recipient, content):
    async with aiosqlite.connect("chatroom.db") as db:
        await db.execute(
            "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
            (sender, recipient, content)
        )
        await db.commit()
        print("Inserted into db")


async def broadcast(message, sender_address):
    for address, writer in clients.items():
        if address != sender_address:
            try:
                writer.write(f"{sender_address}: {message}".encode())
                await writer.drain()
            except ConnectionResetError:
                print(f"Failed to send message to {address}")


if __name__ == '__main__':
    asyncio.run(main())
