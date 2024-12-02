import click
from client import *
from rich.console import Console
from rich.prompt import Prompt

# Initialize Rich Console
console = Console()

@click.command()
@click.option('--host', default='127.0.0.1', help='The server IP address.')
@click.option('--port', default=12345, type=int, help='The server port.')
def main(host, port):
    """
    Main function to run the client application.
    """
    # Instantiate the client
    client = Client(host, port)

    # Connect to the server
    client.connect()

    # Start the message receiving thread
    if client.is_connected:
        threading.Thread(target=client.receive_messages, daemon=True).start()

    # Main loop for user input
    while client.is_connected:
        try:
            message = Prompt.ask("[bold cyan]You[/bold cyan]")
            if message.lower() == "/quit":
                console.print("[bold yellow]Disconnecting...[/bold yellow]")
                client.close()
                break
            client.send_message(message)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Exiting...[/bold yellow]")
            client.close()
            break

if __name__ == "__main__":
    main()

