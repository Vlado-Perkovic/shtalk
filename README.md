# shtalk
A secure chatroom terminal application written in Python

## Roadmap for Developing a Python-Based Terminal Secure Chatroom

### Registration:
        Email Verification: Use Python's smtplib and email libraries to send verification emails to new users.
        CAPTCHA: Implement a text-based CAPTCHA using a library like captcha for Python.
        MFA (Optional): Use pyotp to generate TOTP-based MFA for added security during registration.

### Authentication:
        Password Hashing: Use bcrypt or argon2 (argon2-cffi) to securely hash and verify passwords.
        Session Management: Use PyJWT to generate and validate JSON Web Tokens (JWTs) for handling user sessions.
        MFA on Login: Implement TOTP-based verification using pyotp to add an extra layer of authentication during the login process.

 ###    Message Signing:
        Digital Signatures: Use cryptography or ecdsa to sign messages with ECDSA for non-repudiation and integrity.
        Verification: Implement signature verification using the same library to confirm message authenticity before processing.

 ###    1-to-1 and Group Messaging:
        Encryption Protocol: Implement end-to-end encryption using the Signal Protocol as a model. Use cryptography for basic symmetric and asymmetric encryption primitives or explore Python bindings for libraries like libsignal-protocol-c.
        Message Routing: Implement a message-passing system where the server only routes messages without decrypting them.

 ###    Message Storing:
        Encrypted Storage: Encrypt stored messages using symmetric encryption (e.g., AES) with cryptography or PyCryptoDome.
        Ephemeral Messaging: Implement a self-destruct feature by tracking timestamps and deleting messages after a set duration.
        Implementation: Store encrypted messages in a database such as SQLite or use TinyDB for lightweight data storage.

 ###    End-to-End Encryption (E2EE):
        PFS Implementation: Implement the Double Ratchet algorithm (used in the Signal Protocol) for E2EE with Perfect Forward Secrecy.
        Library: If full implementation is not feasible, use an existing library or adapt code examples available for Python.
        Testing: Validate the implementation with unit tests and peer reviews to ensure encryption works as expected.

 ###    Logging:
        Secure Logging: Use logging in Python with secure practices such as logging to encrypted files. Ensure logs don’t contain sensitive user data.
        Log Rotation: Use logging.handlers.RotatingFileHandler to manage log rotation and avoid excessive disk usage.
        Encryption: Encrypt log files using cryptography for confidentiality.

  ###   Anti-Spam Measures:
        Rate Limiting: Implement rate limiting using redis with a token bucket algorithm or use the limits library to restrict message frequency.
        CAPTCHA: Use a simple CAPTCHA mechanism during user registration and key interactions.
        Monitoring: Implement real-time monitoring using a Python script that analyzes chat activity and flags potential spam behavior for further review.
