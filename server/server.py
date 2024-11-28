import asyncio
import json

HOST = '127.0.0.1'
PORT = 8888

async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    print(f"New connection from {address}")
    
    while True:
        try:
            data = await reader.read(1024)
            if not data:
                print(f"Client {address} disconnected")
                break

            message = data.decode()
            print(f"Recieved from {address} : {message}")

            writer.write("Message received".encode())
            await writer.drain()

        except ConnectionResetError:
            print(f"Connection lost with {address}")
            break
    
    writer.close()
    await writer.wait_closed()
    print(f"Connection closed with {address}")

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Server started on {HOST}:{PORT}")
    
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
