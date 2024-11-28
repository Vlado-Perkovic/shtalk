import asyncio
import json

HOST = '127.0.0.1'
PORT = 8888
clients = {}


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
            message = data.decode()
            print(f"Received from {address}: {message}")
        
            await broadcast(message, address)

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
