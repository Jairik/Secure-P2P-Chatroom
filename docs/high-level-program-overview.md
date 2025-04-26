# Project Functionality Overview

Updated as of 4/26/25

## Files & Purposes

- client.py: Entry point to start the client
- crypto_utils: Encryption, decryption, signing, verification
- config.py: All constants (ports, IPs, key)
- keys/: Directory to store public + private keys
- docs/: Holds references to our resources, reports written, usage directions, etc.
- requirements.txt: List of dependencies

## Visual Structure

```txt
[You] --[Sign]--> --[Encrypt]--> --[UDP Broadcast]-->
        <--[UDP Receive]-- <--[Decrypt]-- <--[Verify Sender]--
```

## Key Management

On the first run, client will generate a Ed25519 keypair and save in keys. Public keys will be distributed manually to verify identities

## Message Sending Structure

- User inputs a message
- Message is signed with the user's Ed25519 private key
- Signature and message are packed together
- Package is encrypted with ChaCha20-Poly1305 using group shared key
- Encrypted message is broadcast over UDP

## Message Receiving Structure

- UDP socket receives an encrypted packet
- Packet is decrypted using the shared group key
- Extracts message and signature from packet
- Use sender's public key to verify the signature
- If verification passes, display the message

## Additional Features

- Usernames (either upon entering chat or associated with public/private key pair)
- Colored terminal to differentiate between user and other messages
