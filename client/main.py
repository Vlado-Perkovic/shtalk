import click
from client import Client

@click.command()
@click.option('--host', default='127.0.0.1', help='The server IP address.')
@click.option('--port', default=12345, type=int, help='The server port.')
def main(host, port):
    """
    Main function to run the client application.
    """
    # Instantiate and connect to the server
    client = Client(host, port)
    client.connect()

    # Get user input for the message to send
    message = input("Enter a message to send to the server: ")
    client.send_message(message)

    # Close the connection
    client.close()

if __name__ == "__main__":
    main()

