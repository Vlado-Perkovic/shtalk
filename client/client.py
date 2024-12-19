import asyncio
import socket
import json
from datetime import datetime
from textual.app import App
from textual.screen import Screen
from textual.widgets import Input, Header, Button, Static
from textual.scroll_view import ScrollView
from textual.containers import Container, Vertical, Horizontal
from textual.binding import Binding
import logging

from enum import Enum

logging.basicConfig(filename='app.log', level=logging.DEBUG)


class ConnectionStatus(Enum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"


class ChatClient:
    """
    Handles networking for the chat client.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_socket = None
        self.is_connected = False
        # self.chat_history = []  # Stores chat messages
        self.chat_histories = {"general": []}  # Track chat histories
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

    def send_message(self, message: str, receiver: str = None):
        """
        Sends a message to the server.
        """
        receiver = receiver or self.current_group

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
                if receiver not in self.chat_histories:
                    # Initialize chat history if it doesn't exist
                    self.chat_histories[receiver] = []
                self.chat_histories[receiver].append(message_json)
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
                receiver = message_json.get("receiver", "general")
                if receiver not in self.chat_histories:
                    self.chat_histories[receiver] = []
                self.chat_histories[receiver].append(message_json)
                return message_json
        except BlockingIOError:
            return None
        except json.JSONDecodeError as e:
            logging.debug(f'err decoding: {e}')

        except Exception as e:
            print(f"Error receiving message: {e}")
            self.is_connected = False
            logging.debug("Line 97")
            self.close()
            return None

    def get_chat_history(self, chat_name: str):
        return self.chat_histories.get(chat_name, [])


class LoginScreen(Screen):
    """
    A screen for user login.
    """
    CSS_PATH = "client.tcss"

    def __init__(self, client: ChatClient):
        super().__init__()
        self.client = client
        self.status_label = Static("Status: Disconnected", id="status_label")

    def compose(self):
        yield Header()
        # with Vertical():
        self.username_input = Input(
            placeholder="Username", id="username_input")
        self.password_input = Input(
            placeholder="Password", id="password_input", password=True)
        self.login_button = Button(label="Login", id="login_button")
        self.register_button = Button(
            label="Register", id="register_button")
        self.status_label = Static(
            "Status: Disconnected", id="status_label")
        self.login_title = Container(Static("Login", id="login_title"))
        self.login_title.styles.height = 3
        self.login_title.styles.background = "gray"
        self.login_title.styles.color = "white"
        self.login_title.styles.text_align = "center"
        yield self.status_label
        yield Container(Static("LOGIN", classes="question"),
                        Vertical(
                            self.username_input,
                            self.password_input,
                            classes="inputs",

        ),

            Horizontal(
                            self.login_button,
                            self.register_button,
                            classes="buttons"),
            id="dialog",
        )

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
            self.status_label.update("Status: Connected")
        elif status == ConnectionStatus.CONNECTING:
            self.status_label.update("Status: Connecting...")
        else:
            self.status_label.update("Status: Disconnected")

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
        self.chat_list = Vertical(id="chat_list")
        self.chat_history = ScrollView(id="chat_history")
        self.message_input = Input(
            placeholder="Type your message...", id="message_input")
        self.send_button = Button(label="Send", id="send_button")

        yield Horizontal(self.chat_list, self.chat_history, id="main_container")
        yield self.message_input
        yield self.send_button

    async def on_mount(self):
        self.update_chat_list()
        self.load_chat_history(self.client.current_group)

    def update_chat_list(self):
        self.chat_list.remove_children()
        for chat in self.client.chat_histories.keys():
            button = Button(label=chat, id=f"chat_{chat}")
            self.chat_list.mount(button)

    def load_chat_history(self, chat_name: str):
        self.chat_history.remove_children()
        self.client.current_group = chat_name
        messages = self.client.get_chat_history(chat_name)
        for message in messages:
            logging.debug(f'MESSAGE -> {message}')
            logging.debug(f'{message["sender"]}, {message["sender"]}, {
                          message["content"]}, {False})')
            asyncio.create_task(self.add_message(
                message["sender"], message["sender"], message["content"], False))

    async def on_button_pressed(self, button: Button):
        if button.button.id.startswith("chat_"):
            chat_name = button.button.id.replace("chat_", "")
            logging.debug(f'chat name is {chat_name}')
            self.load_chat_history(chat_name)
        elif button.button.id == "send_button":
            message = self.message_input.value.strip()
            if message:
                self.client.send_message(message, self.client.current_group)
                await self.add_message("You", self.client.current_group, message, False)
                self.message_input.value = ""

    async def add_message(self, sender: str, receiver: str, message: str, is_system: bool):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {sender}: {
            message}" if not is_system else message
        # if receiver not in self.client.chat_histories.keys():
        #
        #     self.client.chat_histories[receiver] = []
        # self.client.chat_histories[receiver].append(formatted_message)
        logging.debug(f'FORMATTED ---> {formatted_message}')

        await self.chat_history.mount(Static(formatted_message))

    # def action_send_message(self):

    # async def add_message(self, sender: str, message: str, is_system: bool):
    #     """
    #     Add a message to the chat history.
    #     """
    #     timestamp = datetime.now().strftime("%H:%M:%S")
    #     formatted_message = f"[{timestamp}] {sender}: {
    #         message}" if not is_system else f"{message}"
    #     self.client.chat_history.append(formatted_message)
    #
    #     await self.chat_history.mount(Static(formatted_message))


class ChatApp(App):
    """
    A textual TUI for the chat application.
    """
    BINDINGS = [
        Binding("enter", "send_message", "Send Message")
    ]

    def __init__(self, host: str, port: int, **kwargs):
        super().__init__(**kwargs)
        self.client = ChatClient(host, port)

    async def on_load(self):
        self.install_screen(LoginScreen(self.client), name="login")
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
            await screen.add_message(None, None, "Initializing connection...", True)

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
                await screen.add_message(None, None, "Trying to connect...", True)
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
            await self.screen.add_message(None, None, "Server disconnected. Trying to reconnect...", True)
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

    def action_send_message(self):
        logging.debug("AAAAAAAAAAAAAAAAAAAAAA")
        if isinstance(self.screen, ChatScreen):
            message = self.screen.message_input.value.strip()
            if message:
                self.client.send_message(message)
                # await self.screen.add_message("You", message, False)
                asyncio.create_task(
                    self.screen.add_message(self.screen.client.current_group, "You", message, False))
                self.screen.message_input.value = ""

    async def add_message(self, sender: str, message: str, is_system: bool):
        """
            Add a message to the chat history.
            """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {sender}: {
            message}" if not is_system else f"{message}"
        self.client.chat_history.append(formatted_message)
