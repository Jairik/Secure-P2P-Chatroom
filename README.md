# E2E LAN Messaging System

Terminal-based messaging app featuring end-to-end encryption, built to explore core concepts in network security.

## Protocols Used

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
