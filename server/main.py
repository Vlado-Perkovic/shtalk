import asyncio
from handlers import handle_client
from config import HOST, PORT

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
