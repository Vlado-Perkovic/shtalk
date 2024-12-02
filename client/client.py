import socket
import threading
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

# Initialize Rich Console for TUI
console = Console()

class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_socket = None
        self.is_connected = False

    def connect(self):
        """
        Connects to the server.
        """
        try:
            console.print(f"Connecting to server at [bold cyan]{self.host}:{self.port}[/bold cyan]...", style="bold green")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.is_connected = True
            console.print("[bold green]Connected successfully![/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to connect: {e}[/bold red]")
            self.is_connected = False

    def send_message(self, message: str):
        """
        Sends a message to the server.
        """
        if not self.is_connected:
            console.print("[bold red]Not connected to a server.[/bold red]")
            return

        try:
            self.client_socket.sendall(message.encode('utf-8'))
            console.print(f"[bold cyan]You:[/bold cyan] {message}")
        except Exception as e:
            console.print(f"[bold red]Error sending message: {e}[/bold red]")

    def close(self):
        """
        Closes the connection to the server.
        """
        if self.client_socket:
            self.client_socket.close()
            self.is_connected = False
            console.print("[bold yellow]Connection closed.[/bold yellow]")

    def receive_messages(self):
        """
        Receives messages from the server in a separate thread.
        """
        while self.is_connected:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    console.print("[bold yellow]Server disconnected.[/bold yellow]")
                    self.close()
                    break
                console.print(f"[bold magenta]Server:[/bold magenta] {data.decode('utf-8')}")
            except Exception as e:
                console.print(f"[bold red]Error receiving message: {e}[/bold red]")
                self.close()
                break

