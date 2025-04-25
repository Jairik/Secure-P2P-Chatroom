# Section to be updated with new methods

Outdated due to protocol selection, will update later.
<!--

# Project Functionality Overview

On a very high level, this project can be broken up into four main functionalities:

## Server

**Allow multiple clients to connect to the server's IP and port on the same LAN**. This can be acheived by:

- Ensuring all devices are on the same network
- Creating a server (socket) to accept multiple clients

## Clients

Create clients that can **Connect to the server's IP and port, sending/receiving messages**. This can be acheived by connecting to the socket and continuously checking for messages. Additionally, the client must be able to send encrypted messages to the server, and decrypt them once they are received.

## Encryption Layer

**Create methods to be able to encrypt every message locally before sending and decrypting messages once received**. Additionally, create methods to **add message signatures for identity verification**, using public and private keys. Technologies used below in the protocols section.

## Threading & Synchronization

**Utilize threads and other synchronization techniques to allow the server to handle multiple clients at once**.

## Potential Additional Features

If we are ever ***looking*** for additional features to implement, some other cool additions could be:

- **Prompting users for a username once they join**
- **Include timestamps**
- Store all messages in a log
- Colored Terminal Output

## Specific Protocols/Methods Used

### Encryption

**ChaCha20-Poly1305** is fast, modern, and secure. Uses AEAD (Authenticated Ecryption with Associated Data) and is widely used.

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
```

### Identify Verification (Message Signatures)

**Ud25519** is fast and secure, being widely used in applications such as Signal and OpenSSH. Signs a message before sending with the recipient verifying the signature.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
```

### LAN Transport

**UDP Broadcast** is serverless, allowing users to deliver messages to all users on LAN (P2P Architecture).

-->