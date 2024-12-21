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


class ChatInput(Input):
    def key_enter(self) -> None:
        """
        Override the default Enter behavior.
        """
        # Trigger the `send_message` action when Enter is pressed
        self.app.action_send_message()


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
        self.chat_histories = {}  # Track chat histories
        self.current_group = ""  # Default group
        self.connection_status = ConnectionStatus.DISCONNECTED  # Initial status

    async def connect(self):
        logging.debug("connect")
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

    def send_message(self, message_json: {}):
        """
        Sends a message to the server.
        """
        if self.is_connected and self.client_socket:
            try:
                self.client_socket.sendall(
                    json.dumps(message_json).encode("utf-8"))
                recipient = message_json.get("recipient", "")
                # if recipient not in self.chat_histories:
                # Initialize chat history if it doesn't exist
                #     self.chat_histories[recipient] = []
                # self.chat_histories[recipient].append(message_json)
            except Exception as e:
                print(f"Error sending message: {e}")

    def authenticate(self, message_json: {}, timeout: float = 5.0):
        # return False
        if self.is_connected and self.client_socket:
            try:
                # Set timeout for the socket
                self.client_socket.settimeout(timeout)

                # Send authentication request
                self.client_socket.sendall(
                    json.dumps(message_json).encode("utf-8"))

                # Wait for server response
                logging.debug("zapeo")
                response_data = self.client_socket.recv(
                    1024)  # Adjust buffer size if needed
                response_json = json.loads(response_data.decode("utf-8"))

                # Reset the timeout to default (blocking mode)
                self.client_socket.settimeout(None)

                # Check response for success or failure
                if response_json.get("type") == "success":
                    return True
                else:
                    return False
            except socket.timeout:
                logging.debug("Authentication timed out.")
                return None  # Indicate a timeout occurred
            except Exception as e:
                logging.debug(f"Error during authentication: {e}")
                return False

    def register(self, message_json: {}, timeout: float = 5.0):
        # return False
        if self.is_connected and self.client_socket:
            try:
                # Set timeout for the socket
                self.client_socket.settimeout(timeout)

                # Send authentication request
                self.client_socket.sendall(
                    json.dumps(message_json).encode("utf-8"))

                # Wait for server response
                logging.debug("zapeo")
                response_data = self.client_socket.recv(
                    1024)  # Adjust buffer size if needed
                response_json = json.loads(response_data.decode("utf-8"))

                # Reset the timeout to default (blocking mode)
                self.client_socket.settimeout(None)

                # Check response for success or failure
                if response_json.get("type") == "success":
                    return True
                else:
                    return False
            except socket.timeout:
                logging.debug("Authentication timed out.")
                return None  # Indicate a timeout occurred
            except Exception as e:
                logging.debug(f"Error during authentication: {e}")
                return False

    def create_new_chat(self, username):
        self.chat_histories[username] = {"type": "private",
                                         "content": []}
        [logging.debug(f'username: {u}') for u in self.chat_histories.keys()]

    def create_new_group(self, message_json: {}, timeout: float = 5.0):
        if self.is_connected and self.client_socket:
            try:
                # Set timeout for the socket
                self.client_socket.settimeout(timeout)

                # Send authentication request
                self.client_socket.sendall(
                    json.dumps(message_json).encode("utf-8"))

                # Wait for server response
                logging.debug("zapeo")
                response_data = self.client_socket.recv(
                    1024)  # Adjust buffer size if needed
                response_json = json.loads(response_data.decode("utf-8"))

                # Reset the timeout to default (blocking mode)
                self.client_socket.settimeout(None)

                # Check response for success or failure
                if response_json.get("type") == "success":
                    return True
                else:
                    return False
            except socket.timeout:
                logging.debug("Authentication timed out.")
                return None  # Indicate a timeout occurred
            except Exception as e:
                logging.debug(f"Error during authentication: {e}")
                return False

        self.chat_histories[group_name] = {"type": "group",
                                           "content": []}
        [logging.debug(f'username: {u}') for u in self.chat_histories.keys()]

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
                message = json.loads(data.decode("utf-8"))
                logging.debug(f'data: {message}')
                recipient = message.get("recipient", "general")

                if recipient not in self.chat_histories:
                    self.chat_histories[recipient] = []
                self.chat_histories[recipient].append(message)
                return message
        except BlockingIOError:
            return None
        except json.JSONDecodeError as e:
            logging.debug(f'err decoding: {e}')

        except Exception as e:
            logging.debug(f"Error receiving message: {e}")
            self.is_connected = False
            self.close()
            return None

    def get_chat_history(self, chat_name: str):
        return self.chat_histories[chat_name].get("content", "")


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
        logging.debug("STATUS")
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
        self.email_input = Input(
            placeholder="email", id="register_email")
        self.password_input = Input(
            placeholder="Password", id="register_password", password=True)
        self.confirm_password_input = Input(
            placeholder="Confirm Password", id="confirm_password", password=True)
        self.register_button = Button(label="Register", id="register_button")
        self.back_button = Button(label="Back", id="back_button")
        yield self.username_input
        yield self.email_input
        yield self.password_input
        yield self.confirm_password_input
        yield self.register_button
        yield self.back_button

    async def on_button_pressed(self, button: Button):
        if button.button.id == "register_button":
            username = self.username_input.value.strip()
            email = self.email_input.value.strip()
            password = self.password_input.value.strip()
            confirm_password = self.confirm_password_input.value.strip()
            if password == confirm_password:
                await self.app.handle_register(username, email, password)
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
        self.open_chats = []

    def compose(self):
        yield Header()
        self.chat_list_container = Container(id="chat_list_container")
        self.chat_list = Vertical(id="chat_list")
        self.new_chat_button = Button(label="New Chat", id="new_chat_button")
        self.new_group_button = Button(
            label="New Group", id="new_group_button")
        self.chat_history = ScrollView(id="chat_history")
        self.message_input = ChatInput(
            placeholder="Type your message...", id="message_input")
        self.send_button = Button(label="Send", id="send_button")

        self.buttons_panel = Horizontal(
            self.new_chat_button, self.new_group_button,
            id="side_panel_buttons")

        self.left_panel = Vertical(
            self.buttons_panel, self.chat_list, id="side_panel")

        self.main_panel = Horizontal(
            self.left_panel, self.chat_history, id="main_container")

        self.bottom_panel = Horizontal(
            self.message_input, self.send_button, id="bottom_panel")

        yield self.main_panel

        yield self.bottom_panel

    async def on_mount(self):
        await self.update_chat_list()
        # await self.load_chat_history(self.client.current_group)

    async def update_chat_list(self):

        await self.chat_list.remove_children()
        # for chat in self.client.chat_histories.keys():
        logging.debug("PUSIGA")

        for chat in self.client.chat_histories.keys():
            logging.debug(f'chat: {chat}')
            button = Button(label=chat, id=f"chat_{chat}")
            self.chat_list.mount(button)

    async def load_chat_history(self, chat_name: str):
        await self.chat_history.remove_children()
        self.client.current_group = chat_name
        messages = self.client.get_chat_history(chat_name)
        for message in messages:
            logging.debug(f'MESSAGE -> {message}')
            await self.add_message(message)

    async def on_button_pressed(self, button: Button):

        if button.button.id.startswith("chat_"):
            logging.debug("kruac button pressed")
            chat_name = button.button.id.replace("chat_", "")
            logging.debug(f'chat name is {chat_name}')
            await self.load_chat_history(chat_name)

        elif button.button.id == "send_button":
            logging.debug("send_button pressed")

            message = self.message_input.value.strip()
            if message:
                chat_type = self.client.chat_histories[self.client.current_group].get(
                    "type", "")
                if chat_type == "":
                    logging.debug("ujebo si ga brate")
                    return
                message_json = {
                    "type": chat_type,
                    "sender": "vlado",
                    "recipient": self.client.current_group,
                    "timestamp": datetime.now().isoformat(),
                    "message": {
                        "ciphertext": message,
                        "iv": "base64_encoded_initialization_vector",
                        "signature": "base64_encoded_signature",
                    },  # This will be encrypted in the future
                    # Replace with the actual username
                }

                self.client.send_message(message_json)
                await self.add_message(json.dumps(message_json))
                self.message_input.value = ""

        elif button.button.id == "new_chat_button":
            logging.debug("new_chat_button pressed")

            # Show an input field to type the username
            self.new_chat_input = Input(
                placeholder="Enter username...", id="new_chat_input")
            self.confirm_new_chat_button = Button(
                label="Start Chat", id="confirm_new_chat_button")
            self.left_panel.mount(self.new_chat_input)
            self.left_panel.mount(self.confirm_new_chat_button)

        elif button.button.id == "confirm_new_chat_button":
            username = self.new_chat_input.value.strip()
            if username:
                # Send request to the server to create a new chat
                self.client.create_new_chat(
                    username)  # Implement on the server
                [logging.debug(f'u: {u}')
                 for u in self.client.chat_histories.keys()]
                # if new_chat:  # Assume the server returns the new chat details
                await self.update_chat_list()
                logging.debug("koji kruac")

            # Remove the input field and button after confirmation
                self.new_chat_input.remove()
                self.confirm_new_chat_button.remove()
                # self.chat_list_container.remove(self.new_chat_input)
                # self.chat_list_container.remove(
                #     self.confirm_new_chat_button)

        elif button.button.id == "new_group_button":
            logging.debug("new_group_button pressed")
            # Open inputs for group chat creation
            self.group_name_input = Input(
                placeholder="Enter group name...", id="group_name_input")
            self.group_members_input = Input(
                placeholder="Enter usernames (comma-separated)...", id="group_members_input")
            self.confirm_new_group_button = Button(
                label="Create Group", id="confirm_new_group_button")

            self.left_panel.mount(self.group_name_input)
            self.left_panel.mount(self.group_members_input)
            self.left_panel.mount(self.confirm_new_group_button)

        elif button.button.id == "confirm_new_group_button":
            # Handle group chat creation
            group_name = self.group_name_input.value.strip()
            members = self.group_members_input.value.strip()

            if group_name and members:
                member_list = [m.strip() for m in members.split(",")]
                new_group = self.app.handle_create_group(
                    group_name, members=member_list)
                # if new_group:
                await self.update_chat_list()

            self.group_name_input.remove()
            self.group_members_input.remove()
            self.confirm_new_group_button.remove()

    async def add_message(self, message_json: json):
        try:
            sender = message_json.get("sender", "Unknown")
            content = message_json.get("message", "").get("ciphertext", "")
            timestamp = message_json.get(
                "timestamp", datetime.now().strftime("%H:%M:%S"))
            formatted_message = f"[{timestamp}] {sender}: {content}"
            await self.chat_history.mount(Static(formatted_message))
        except Exception as e:
            logging.error(f"Error rendering message: {e}")

    async def add_sys_message(self, err_msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [SYSTEM]: {err_msg}"

        await self.chat_history.mount(Static(formatted_message))


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
            await screen.add_sys_message("Initializing connection...")

        await asyncio.sleep(0.1)  # Ensure TUI has time to render initially

        while not self.client.is_connected:
            logging.debug("AJMO")
            try:
                await self.client.connect()
                if self.client.is_connected:
                    if isinstance(screen, ChatScreen):
                        await screen.add_sys_message("Connected to the chat server.")
                    asyncio.create_task(self.receive_messages())
                    break
            except Exception as e:
                if isinstance(screen, ChatScreen):
                    await screen.add_sys_message(f"Connection error: {e}")

            if isinstance(screen, ChatScreen):
                await screen.add_sys_message("Trying to connect...")
            await asyncio.sleep(retry_interval)

    async def receive_messages(self):
        logging.debug("RECEIVE_MESSAGES")
        """
        Continuously listens for incoming messages from the server.
        """
        if isinstance(self.screen, ChatScreen):
            while self.client.is_connected:
                message = self.client.receive_messages()
                if message:
                    # await self.screen.add_message("Server", message.get("content", "kurac"), False)
                    logging.debug(f'AJMOO {message}')
                    await self.screen.add_message(message)

                await asyncio.sleep(0.1)  # Prevent tight loop
        # if out of the loop, try to reconnect
            await self.handle_disconnect()

    async def handle_disconnect(self):
        """
        Handles the case when the server disconnects.
        """
        if isinstance(self.screen, ChatScreen):

            await self.screen.add_sys_message("Server disconnected. Trying to reconnect...")
        logging.debug("Server disconnected. Trying to reconnect...")
        self.client.close()
        await self.attempt_connection()

    async def handle_register(self, username: str, email: str, password: str):
        if not self.client.is_connected:
            await self.handle_disconnect()

        if self.client.is_connected:
            # Simulate sending login credentials to the server
            try:
                register_payload = {
                    "type": "register",
                    "username": username,
                    "email": email,
                    "password": password,
                }
                if self.client.register(register_payload):
                    logging.debug("REGISTER SUCCESS")
                    await self.push_screen(LoginScreen(self.client))
                else:
                    logging.debug("REGISTER FAIL")

            except Exception as e:
                await self.show_error(f"Error during login: {str(e)}")
        else:
            await self.show_error("Could not connect to the server. Please try again later.")

    async def handle_login(self, username: str, password: str):
        """
        Handles the login process.
        """
        if not self.client.is_connected:
            await self.handle_disconnect()

        if self.client.is_connected:
            # Simulate sending login credentials to the server
            try:

                public_key = ""
                with open('.ssh/id_ed25519.pub', 'r') as f:
                    public_key = f.read()

                login_payload = {
                    "type": "login",
                    "username": username,
                    "password": password,
                    "public_key": public_key,
                }
                if self.client.authenticate(login_payload, 5.0):
                    logging.debug("LOGIN SUCCESS")
                # if True:
                    await self.push_screen(ChatScreen(self.client))
                else:
                    await self.show_error("Invalid login credentials")

            except Exception as e:
                await self.show_error(f"Error during login: {str(e)}")
        else:
            await self.show_error("Could not connect to the server. Please try again later.")

    async def handle_create_group(self, group_name: str):
        if not self.client.is_connected:
            await self.handle_disconnect()

        if self.client.is_connected:
            try:
                new_group_payload = {
                    "type": "new_group",
                    "username": "vlado",
                    "group_name": group_name,
                    "description": ""
                }
                self.client.create_new_group(new_group_payload)

            except Exception as e:
                await self.show_error(f"Error during login: {str(e)}")
        else:
            await self.show_error("Could not connect to the server. Please try again later.")

    async def handle_add_user_to_group(self, username: str, group_name: str):
        if not self.client.is_connected:
            await self.handle_disconnect()

        if self.client.is_connected:
            try:
                new_group_payload = {
                    "type": "add",
                    "group_name": group_name,
                    "username": username,
                }
                self.client.add_user_to_group(new_group_payload)

            except Exception as e:
                await self.show_error(f"Error during login: {str(e)}")
        else:
            await self.show_error("Could not connect to the server. Please try again later.")

    async def show_error(self, message: str):
        logging.error(message)
        # Implement error display logic (e.g., via a modal or notification bar)

    def action_send_message(self):
        if isinstance(self.screen, ChatScreen):
            message = self.screen.message_input.value.strip()
            if message:
                chat_type = self.client.chat_histories[self.client.current_group].get(
                    "type", "")
                if chat_type == "":
                    logging.debug("ujebo si ga brate")
                    return
                message_json = {
                    "type": chat_type,
                    "sender": "vlado",
                    "recipient" if chat_type == "private" else "group_name": self.client.current_group,
                    "timestamp": datetime.now().isoformat(),
                    "message": {
                        "ciphertext": message,
                        "iv": "base64_encoded_initialization_vector",
                        "signature": "base64_encoded_signature",
                    },  # This will be encrypted in the future
                }
                self.client.send_message(message_json)
                # await self.screen.add_message("You", message, False)
                asyncio.create_task(
                    self.screen.add_message(message_json))
                self.screen.message_input.value = ""
