# Project Functionality Overview

On a very high level, this project can be broken up into four main functionalities:

## Server

**Allow multiple clients to connect to the server's IP and port on the same LAN**. This can be acheived by:

- Ensuring all devices are on the same network
- Creating a server (socket) to accept multiple clients

## Clients

Create clients that can **Connect to the server's IP and port, sending/receiving messages**. This can be acheived by connecting to the socket and continuously checking for messages. Additionally, the client must be able to send encrypted messages to the server, and decrypt them once they are received.

## Encryption Layer

**Create methods to be able to encrypt every message locally before sending and decrypting messages once received**. In order to accomplish this, we should create genralized wrapper functions, and determine what the best encryption protocol is (will update after doing some research).

## Threading & Synchronization

**Utilize threads and other synchronization techniques to allow the server to handle multiple clients at once**.

## Potential Additional Features

If we are ever ***looking*** for additional features to implement, some other cool additions could be:

- **Prompting users for a username once they join**
- **Include timestamps**
- Store all messages in a log
- Colored Terminal Output
- Private Messaging (eg. /msg *usr* *msg*) (Use user/session tracking on the server side)
- Add a web interface (would be really cool, but introduces some more complexity with communicating with backend)
