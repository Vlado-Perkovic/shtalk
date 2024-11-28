import sqlite3

def test_storage():
    """Test to verify message storage in SQLite database."""
    db_path = "../chatroom.db"

    # Create a connection to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        print("Starting test for message storage...")
        
        # Insert a test message
        sender = "Client 1"
        recipient = "Client 2"
        content = "Hello, this is a test message!"
        cursor.execute(
            "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
            (sender, recipient, content)
        )
        conn.commit()

        # Fetch the last inserted message
        cursor.execute("SELECT sender, recipient, content, timestamp FROM messages ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        
        # Verify the result
        assert result is not None, "No message found in the database"
        assert result[0] == sender, f"Sender mismatch: {result[0]} != {sender}"
        assert result[1] == recipient, f"Recipient mismatch: {result[1]} != {recipient}"
        assert result[2] == content, f"Content mismatch: {result[2]} != {content}"
        print("Message storage test passed!")
    
    except Exception as e:
        print(f"Test failed: {e}")
    
    finally:
        conn.close()

if __name__ == "__main__":
    test_storage()
