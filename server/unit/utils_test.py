import aiosqlite
import asyncio
import unittest
import sys
import os
from unittest.mock import MagicMock 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import (
    read_all_clients, send_private_message, send_group_message, fetch_history,
    store_message_single, store_message_group, get_users_in_group, get_groups
)

class TestDatabase(unittest.TestCase):

    def setUp(self):
        # Set up the in-memory database and create tables before each test
        loop = asyncio.get_event_loop()
        self.loop = loop
        self.db = loop.run_until_complete(aiosqlite.connect(":memory:"))
        loop.run_until_complete(self.db.executescript('''
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, is_verified INTEGER);
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY, 
                sender_id INTEGER, 
                recipient_id INTEGER, 
                group_name TEXT, 
                ciphertext TEXT, 
                iv TEXT, 
                signature TEXT, 
                sent_at TEXT
            );
            CREATE TABLE group_members (user_id INTEGER, group_name TEXT);
            CREATE TABLE groups (id INTEGER PRIMARY KEY, group_name TEXT);
        '''))
        self.loop.run_until_complete(self.db.commit())

    def tearDown(self):
        # Close the database after each test to ensure isolation
        self.loop.run_until_complete(self.db.close())

    def test_read_all_clients(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (username, email, is_verified) VALUES ('testuser', 'test@example.com', 1)"))
        loop.run_until_complete(self.db.commit())
        
        clients = loop.run_until_complete(read_all_clients(self.db))
        print(clients)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[1]['username'], 'testuser')

    def test_send_private_message_success(self):
        loop = self.loop

        # Insert test users into the database
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username, email, is_verified) VALUES (1, 'sender', 'sender@example.com', 1)"))
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username, email, is_verified) VALUES (2, 'recipient', 'recipient@example.com', 1)"))
        loop.run_until_complete(self.db.commit())

        # Create mock writer objects for sender and recipient
        sender_writer = MagicMock()
        target_writer = MagicMock()

        # Mock clients dictionary directly
        self.clients = {'sender': sender_writer, 'recipient': target_writer}

        # Prepare the message to send
        message = {
            "recipient": "recipient",
            "sender": "sender",  # Make sure sender is correct
            "message": {"ciphertext": "secret", "iv": "random_iv", "signature": "signature"},
            "timestamp": "2024-12-19T12:00:00Z"
        }

        # Run the function to send the private message
        loop.run_until_complete(send_private_message(message, self.db))

        # Check if the message was inserted into the database
        result = loop.run_until_complete(self.db.execute_fetchall("SELECT * FROM messages"))
        self.assertEqual(len(result), 1)

        # Check that the mock target_writer was called to send the message
        target_writer.write.assert_called_once_with(b"Private message from sender: {'ciphertext': 'secret', 'iv': 'random_iv', 'signature': 'signature'}\n")
        target_writer.drain.assert_called_once()

        # Check that the message was stored in the database with the correct values
        message_row = result[0]
        self.assertEqual(message_row[4], 'secret')  # Check ciphertext
        self.assertEqual(message_row[5], 'random_iv')  # Check iv


    def test_send_group_message_success(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (1, 'sender')"))
        loop.run_until_complete(self.db.execute("INSERT INTO groups (id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.execute("INSERT INTO group_members (user_id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.commit())

        message = {
            "sender": "sender",
            "group": "test_group",
            "message": {"ciphertext": "secret", "iv": "random_iv", "signature": "signature"},
            "timestamp": "2024-12-19T12:00:00Z"
        }
        loop.run_until_complete(send_group_message(message, self.db))
        result = loop.run_until_complete(self.db.execute_fetchall("SELECT * FROM messages"))
        self.assertEqual(len(result), 1)

    def test_fetch_history_private(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (100, 'sender')"))
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (101, 'recipient')"))
        loop.run_until_complete(self.db.execute(
            """
            INSERT INTO messages 
            (message_id, sender_id, recipient_id, ciphertext, iv, signature, sent_at) 
            VALUES ('2133211', 100, 101, 'secret', 'random_iv', 'signature', '2024-12-19T12:00:00Z')
            """
        ))
        loop.run_until_complete(self.db.commit())

        messages = loop.run_until_complete(fetch_history(100, 101, 'private', self.db))
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]['ciphertext'], 'secret')

    def test_fetch_history_group(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (1, 'sender')"))
        loop.run_until_complete(self.db.execute("INSERT INTO groups (id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.execute(
            """
            INSERT INTO messages 
            (message_id, sender_id, group_name, ciphertext, iv, signature, sent_at) 
            VALUES ('msg1', 1, 'test_group', 'secret', 'random_iv', 'signature', '2024-12-19T12:00:00Z')
            """
        ))
        loop.run_until_complete(self.db.commit())

        messages = loop.run_until_complete(fetch_history(1, 'test_group', 'group', self.db))
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]['ciphertext'], 'secret')

    def test_get_users_in_group(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (1, 'user1')"))
        loop.run_until_complete(self.db.execute("INSERT INTO group_members (user_id, group_name) VALUES (1 , 'test_group')"))
        loop.run_until_complete(self.db.commit())
        members = loop.run_until_complete(get_users_in_group('test_group', self.db))
        print(members)
        self.assertIn(1, members)

    def test_get_groups(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO groups (id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.commit())

        groups = loop.run_until_complete(get_groups(self.db))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0], (1,))

    def test_store_message_single(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (1, 'user1')"))
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (2, 'user2')"))
        loop.run_until_complete(self.db.commit())

        message_data = {
            "message_id": "msg1",
            "sender": "user1",
            "recipient": "user2",
            "content":{
                "ciphertext": "secret",
                "iv": "random_iv",
                "signature": "signature",
                "key" : "key"
            },
            "sent_at": "2024-12-19T12:00:00Z"
        }
        loop.run_until_complete(store_message_single("user1","user2",message_data["content"],message_data["sent_at"], self.db))
        result = loop.run_until_complete(self.db.execute_fetchall("SELECT * FROM messages"))
        self.assertEqual(len(result), 1)

    def test_store_message_group(self):
        loop = self.loop
        loop.run_until_complete(self.db.execute("INSERT INTO users (id, username) VALUES (1, 'user1')"))
        loop.run_until_complete(self.db.execute("INSERT INTO groups (id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.execute("INSERT INTO group_members (user_id, group_name) VALUES (1, 'test_group')"))
        loop.run_until_complete(self.db.commit())

        message_data = {
            "message_id": "msg1",
            "sender_id": "user1",
            "group_name": "test_group",
            "content":{
                "ciphertext": "secret",
                "iv": "random_iv",
                "signature": "signature",
                "key" : "key"
            },
            "sent_at": "2024-12-19T12:00:00Z"
        }
        loop.run_until_complete(store_message_group("user1",message_data["content"],message_data["sent_at"], "test_group",self.db))
        result = loop.run_until_complete(self.db.execute_fetchall("SELECT * FROM messages"))
        self.assertEqual(len(result), 1)

if __name__ == '__main__':
    unittest.main()
