import asyncio
import json  # Ensure we use the JSON library for serialization

async def client_task(message, target, server_host="localhost", server_port=8888, client_port=None):
    """
    Simulates a client sending a private message to another client identified by their address and port.
    """
    if client_port is None:
        client_port = 0  # Let the OS choose a port if not specified

    # Create a client connection on the specified port
    reader, writer = await asyncio.open_connection(server_host, server_port, local_addr=(server_host, client_port))

    try:
        # Send a private message to the specified target address and port
        message_data = {
            "type": "private",
            "target": target,  # Target is ('address', port)
            "content": message
        }

        # Serialize message to JSON and send it
        writer.write((json.dumps(message_data) + "\n").encode("utf-8"))
        await writer.drain()
        
        # Wait for response from the server
        response = await reader.readline()
        print(f"Client {client_port} received: {response.decode().strip()}")
    
    finally:
        writer.close()
        await writer.wait_closed()
        reader.close()
        await reader.wait_closed()


async def test_routing_logic():
    """
    Test function to simulate two clients sending messages to each other using address and port.
    """
    print("Starting test for routing logic...")

    # Define the target addresses and ports
    target1 = ('127.0.0.1', 55001)  # Target for Client 2
    target2 = ('127.0.0.1', 55002)  # Target for Client 1

    # Simulate two clients with separate tasks
    task1 = asyncio.create_task(client_task("Hello, Client 2!", target1, client_port=55002))  # Client 1 sending to Client 2
    task2 = asyncio.create_task(client_task("Hi, Client 1!", target2, client_port=55001))  # Client 2 sending to Client 1

    await asyncio.gather(task1, task2)  # Run both clients concurrently

if __name__ == "__main__":
    asyncio.run(test_routing_logic())
