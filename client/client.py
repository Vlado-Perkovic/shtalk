import socket

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        """Connect to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")
        except Exception as e:
            print(f"Failed to connect to server: {e}")

    def send_message(self, message):
        """Send a message to the server."""
        try:
            if self.sock:
                self.sock.sendall(message.encode('utf-8'))
                print(f"Message sent: {message}")
            else:
                print("No active connection to the server.")
        except Exception as e:
            print(f"Error sending message: {e}")

    def close(self):
        """Close the connection."""
        if self.sock:
            self.sock.close()
            print("Connection closed.")

