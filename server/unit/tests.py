import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import pyotp
import bcrypt
import jwt
import json
from server import (
    setup_mfa,
    verify_mfa,
    register_user,
    login_user,
    send_private_message,
    send_group_message,
    store_message,
    clients,
    groups,
    JWT_SECRET,
)

class TestChatServer(unittest.IsolatedAsyncioTestCase):

    async def test_setup_mfa(self):
        secret = setup_mfa()
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 16)  # Default base32 length

    async def test_verify_mfa(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        self.assertTrue(verify_mfa(secret, code))  # Should be valid for the generated code
        self.assertFalse(verify_mfa(secret, 'wrong_code'))  # Invalid code should fail

    @patch('server.aiosqlite.connect')  # Adjusted import path
    async def test_register_user_success(self, mock_db):
        mock_db.execute.return_value = MagicMock()
        mock_db.fetch_one.return_value = None  # Simulate no user existing

        response = register_user("testuser", "test@example.com", "password", mock_db)
        self.assertEqual(response, {"success": "User registered successfully"})

    @patch('server.aiosqlite.connect', new_callable=AsyncMock)  # Adjusted import path
    async def test_register_user_existing_username(self, mock_db):
        mock_db.fetch_one.return_value = {"username": "testuser"}  # Simulate user already exists
        response = await register_user("testuser", "test@example.com", "password", mock_db)
        self.assertEqual(response, {"error": "Username or email already exists"})
    @patch('server.aiosqlite.connect', new_callable=AsyncMock)  # Adjusted import path
    async def test_login_user_success(self, mock_db):
        mock_db.fetch_one.return_value = {
            "id": 1,
            "username": "testuser",
            "password_hash": bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode(),
            "is_verified": True,
            "mfa_secret": pyotp.random_base32()
        }
        
        # Await the login_user coroutine to get the actual result
        response = await login_user("testuser", "password", "123456", mock_db)
        
        # Now you can assert that the response contains "token"
        self.assertIn("token", response)

    @patch('server.aiosqlite.connect')  # Adjusted import path
    async def test_login_user_invalid_password(self, mock_db):
        mock_db.fetch_one.return_value = {"id": 1, "username": "testuser", "password_hash": bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode(), "is_verified": True, "mfa_secret": pyotp.random_base32()}
        response = login_user("testuser", "wrong_password", "123456", mock_db)
        self.assertEqual(response, {"error": "Invalid username or password"})

    @patch('server.aiosqlite.connect')  # Adjusted import path
    async def test_login_user_invalid_mfa(self, mock_db):
        secret = pyotp.random_base32()
        mock_db.fetch_one.return_value = {"id": 1, "username": "testuser", "password_hash": bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode(), "is_verified": True, "mfa_secret": secret}
        response = login_user("testuser", "password", "wrong_mfa_code", mock_db)
        self.assertEqual(response, {"error": "Invalid MFA code"})

    @patch('server.aiosqlite.connect')  # Adjusted import path
    async def test_send_private_message_success(self, mock_db):
        sender_address = ('127.0.0.1', 8888)
        target_address = ('127.0.0.1', 9999)
        clients[sender_address] = MagicMock()
        clients[target_address] = MagicMock()
        message = {'type': 'private', 'target': target_address, 'content': 'Hello!'}

        response = send_private_message(message, sender_address, mock_db)
        self.assertTrue(clients[target_address].write.called)  # Message should be sent

    @patch('server.aiosqlite.connect')  # Adjusted import path
    async def test_send_group_message_success(self, mock_db):
        sender_address = ('127.0.0.1', 8888)
        group_name = 'group1'
        content = "Hello, Group!"
        groups[group_name] = [sender_address]

        message = {'type': 'group', 'target': group_name, 'content': content}
        response = send_group_message(message, sender_address, mock_db)
        self.assertTrue(clients[sender_address].write.called)  # Message should be sent to sender

    @patch('server.aiosqlite.connect', new_callable=AsyncMock)   # Adjusted import path
    async def test_store_message_success(self, mock_db):
        mock_db.execute.return_value = MagicMock()
        await store_message("user1", "user2", "Test message", mock_db)
        mock_db.execute.assert_called_with(
            "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)", ("user1", "user2", "Test message")
        )

    async def test_message_format(self):
        message = json.dumps({"type": "login", "username": "test", "password": "password"})
        self.assertIsInstance(message, str)
        self.assertNotEqual(message, "")

    def test_invalid_message_format(self):
        message = "Invalid message format"
        with self.assertRaises(json.JSONDecodeError):
            json.loads(message)

if __name__ == "__main__":
    unittest.main()
