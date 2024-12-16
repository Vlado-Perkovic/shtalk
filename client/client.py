import asyncio
import socket
import json
from datetime import datetime
from textual.app import App
from textual.screen import Screen
from textual.widgets import Input, Header, Button, Static
from textual.scroll_view import ScrollView
import logging

from enum import Enum

logging.basicConfig(filename='app.log', level=logging.DEBUG)


class ConnectionStatus(Enum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"


def update_text(self, text, style):

    if style == "green":
        print(f"\033[92m{text}\033[0m")  # Green text
    elif style == "yellow":
        print(f"\033[93m{text}\033[0m")  # Yellow text
    else:
        print(f"\033[91m{text}\033[0m")  # Red text


class ChatClient:
    """
    Handles networking for the chat client.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_socket = None
        self.is_connected = False
        self.chat_history = []  # Stores chat messages
        self.current_group = "general"  # Default group
        self.connection_status = ConnectionStatus.DISCONNECTED  # Initial status

    async def connect(self):
        """
        Asynchronously connects to the server.
        """
        self.connection_status = ConnectionStatus.CONNECTING
        try:
            self.client_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            # Make the socket non-blocking
            self.client_socket.setblocking(False)
            await asyncio.get_event_loop().sock_connect(self.client_socket, (self.host, self.port))
            self.is_connected = True
            self.connection_status = ConnectionStatus.CONNECTED
        except Exception as e:
            self.is_connected = False
            self.connection_status = ConnectionStatus.DISCONNECTED
            logging.debug('LINE: 40')
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None

    def send_message(self, message: str, receiver: str = "general"):
        """
        Sends a message to the server.
        """
        if self.is_connected and self.client_socket:
            try:
                message_json = {
                    "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
                    "content": message,  # This will be encrypted in the future
                    "timestamp": datetime.now().isoformat(),
                    "receiver": receiver,
                    "sender": "you",  # Replace with the actual username
                }
                self.client_socket.sendall(
                    json.dumps(message_json).encode("utf-8"))
            except Exception as e:
                print(f"Error sending message: {e}")

    def close(self):
        """
        Closes the connection to the server.
        """
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                pass

            finally:
                self.client_socket = None
                self.is_connected = False
                self.connection_status = ConnectionStatus.DISCONNECTED
                logging.debug("Line 76")

    def receive_messages(self):
        """
        Receives messages from the server.
        """
        if not self.is_connected:
            return None

        try:
            data = self.client_socket.recv(1024)
            if data:
                # return data.decode("utf-8")
                # message_json = json.loads(data.decode("utf-8"))
                message_json = data.decode("utf-8")
                logging.debug(f'data: {message_json}')
                return message_json
        except BlockingIOError:
            return None
        except Exception as e:
            print(f"Error receiving message: {e}")
            self.is_connected = False
            logging.debug("Line 97")
            self.close()
            return None


class LoginScreen(Screen):
    """
    A screen for user login.
    """

    def compose(self):
        yield Header()
        yield Static("Login", id="login_title")
        self.username_input = Input(
            placeholder="Username", id="username_input")
        self.password_input = Input(
            placeholder="Password", id="password_input", password=True)
        self.login_button = Button(label="Login", id="login_button")
        self.register_button = Button(label="Register", id="register_button")
        self.status_label = Static("Status: Disconnected", id="status_label")
        yield self.status_label
        yield self.username_input
        yield self.password_input
        yield self.login_button
        yield self.register_button

    async def on_button_pressed(self, button: Button):
        if button.button.id == "login_button":
            username = self.username_input.value.strip()
            password = self.password_input.value.strip()
            logging.debug(f'user: {username} \npass:{password}')
            await self.app.handle_login(username, password)
        elif button.button.id == "register_button":
            await self.app.push_screen("register")

    async def update_status(self):
        """
        Periodically updates the connection status label.
        """
        status = self.client.connection_status
        if status == ConnectionStatus.CONNECTED:
            self.status_label.update("Status: Connected", style="green")
        elif status == ConnectionStatus.CONNECTING:
            self.status_label.update("Status: Connecting...", style="yellow")
        else:
            self.status_label.update("Status: Disconnected", style="red")

    async def on_mount(self):
        # Run status updates in the background
        asyncio.create_task(self.status_updater())

    async def status_updater(self):
        while True:
            await self.update_status()
            await asyncio.sleep(0.5)


class RegisterScreen(Screen):
    """
    A screen for user registration.
    """

    def compose(self):
        yield Header()
        yield Static("Register", id="register_title")
        self.username_input = Input(
            placeholder="Username", id="register_username")
        self.password_input = Input(
            placeholder="Password", id="register_password", password=True)
        self.confirm_password_input = Input(
            placeholder="Confirm Password", id="confirm_password", password=True)
        self.register_button = Button(label="Register", id="register_button")
        self.back_button = Button(label="Back", id="back_button")
        yield self.username_input
        yield self.password_input
        yield self.confirm_password_input
        yield self.register_button
        yield self.back_button

    async def on_button_pressed(self, button: Button):
        if button.button.id == "register_button":
            username = self.username_input.value.strip()
            password = self.password_input.value.strip()
            confirm_password = self.confirm_password_input.value.strip()
            if password == confirm_password:
                await self.app.handle_register(username, password)
            else:
                await self.app.show_error("Passwords do not match")
        elif button.button.id == "back_button":
            await self.app.pop_screen()


class ChatScreen(Screen):
    """
    The main chat interface.
    """

    def __init__(self, client):
        super().__init__()
        self.client = client

    def compose(self):
        yield Header()
        self.chat_history = ScrollView()
        self.message_input = Input(
            placeholder="Type your message...", id="message_input")
        self.send_button = Button(label="Send", id="send_button")
        yield self.chat_history
        yield self.message_input
        yield self.send_button

    async def on_button_pressed(self, button: Button):
        if button.button.id == "send_button":
            message = self.message_input.value.strip()
            if message:
                self.client.send_message(message)
                await self.add_message("You", message, False)
                self.message_input.value = ""

    async def add_message(self, sender: str, message: str, is_system: bool):
        """
        Add a message to the chat history.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {sender}: {
            message}" if not is_system else f"{message}"
        self.client.chat_history.append(formatted_message)

        await self.chat_history.mount(Static(formatted_message))


class ChatApp(App):
    """
    A textual TUI for the chat application.
    """

    def __init__(self, host: str, port: int, **kwargs):
        super().__init__(**kwargs)
        self.client = ChatClient(host, port)

    async def on_load(self):
        self.install_screen(LoginScreen(), name="login")
        self.install_screen(RegisterScreen(), name="register")
        self.push_screen("login")

    async def on_mount(self):
        # Attempt to connect in the background
        asyncio.create_task(self.attempt_connection())

    async def attempt_connection(self, retry_interval=2):
        """
        Try to connect to the server periodically until successful.
        """
        screen = self.screen
        if isinstance(screen, ChatScreen):
            await screen.add_message(None, "Initializing connection...", True)

        await asyncio.sleep(0.1)  # Ensure TUI has time to render initially

        while not self.client.is_connected:
            try:
                await self.client.connect()
                if self.client.is_connected:
                    if isinstance(screen, ChatScreen):
                        await screen.add_message(None, "Connected to the chat server.", True)
                    asyncio.create_task(self.receive_messages())
                    break
            except Exception as e:
                if isinstance(screen, ChatScreen):
                    await screen.add_message(None, f"Connection error: {e}", True)

            if isinstance(screen, ChatScreen):
                await screen.add_message(None, "Trying to connect...", True)
            await asyncio.sleep(retry_interval)

    async def receive_messages(self):
        """
        Continuously listens for incoming messages from the server.
        """
        while self.client.is_connected:
            message = self.client.receive_messages()
            if message:
                logging.debug(f'AJMOO {message}')
                if isinstance(self.screen, ChatScreen):
                    # await self.screen.add_message("Server", message.get("content", "kurac"), False)
                    await self.screen.add_message("Server", message, False)

            await asyncio.sleep(0.1)  # Prevent tight loop
        # if out of the loop, try to reconnect
        await self.handle_disconnect()

    async def handle_disconnect(self):
        """
        Handles the case when the server disconnects.
        """
        if isinstance(self.screen, ChatScreen):
            await self.screen.add_message(None, "Server disconnected. Trying to reconnect...", True)
        logging.debug("Server disconnected. Trying to reconnect...")
        self.client.close()
        await self.attempt_connection()

    async def handle_login(self, username: str, password: str):
        """
        Handles the login process.
        """
        if not self.client.is_connected:
            await self.handle_disconnect()

        if self.client.is_connected:
            # Simulate sending login credentials to the server
            try:
                login_payload = {
                    "type": "login",
                    "username": username,
                    "password": password,
                }
                self.client.send_message(json.dumps(login_payload))

                # Simulate server response (you should handle real responses)
                if username == "user" and password == "pass":
                    await self.push_screen(ChatScreen(self.client))
                else:
                    await self.show_error("Invalid login credentials")

            except Exception as e:
                await self.show_error(f"Error during login: {str(e)}")
        else:
            await self.show_error("Could not connect to the server. Please try again later.")

    async def show_error(self, message: str):
        logging.error(message)
        # Implement error display logic (e.g., via a modal or notification bar)

    async def action_send_message(self):
        """
        Handles sending a message when the Enter key is pressed.
        """
        message = self.message_input.value.strip()
        if message:
            self.client.send_message(message)
            await self.add_message("You", message, False)
            self.message_input.value = ""

    async def add_message(self, sender: str, message: str, is_system: bool):
        """
        Add a message to the chat history.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {sender}: {
            message}" if not is_system else f"{message}"
        self.client.chat_history.append(formatted_message)
