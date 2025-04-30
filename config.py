''' Constants such as port numbers, IP addresses, and keys '''

import os  # Random key generation

# Multicast settings for p2p communication
MCAST_PORT = 5000  # Port for all peers to listen to
MCAST_GRP = '224.1.1.1'  # Multicast group address shared among all clients

# Setting buffer size for receiving data through socket (4kB)
BUFFER_SIZE = 4096 

# CHACHA20 Settings
KEY_SIZE = 32  # Key size in bytes for CHACHA20
NONCE_SIZE = 12  # Nonce (Number Used Once) size in bytes for CHACHA20 (for added security)

# Generate a random key for CHACHA20 encryption
CHACHA20_KEY = os.urandom(KEY_SIZE)
