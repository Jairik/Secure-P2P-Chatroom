''' Constants such as ports, IPs, keys '''

import os  # For random key generation
import socket  # For determining the local IP address

# Defining script to get the local IP address
def get_local_ip():
    """Get the local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
    try:
        s.connect(("8.8.8.8", 80))  # Connect to a public DNS server (Google DNS)
        ip = s.getsockname()[0]  # Get the local IP address
    except Exception:
        ip = '127.0.0.1'  # Fallback to localhost if a socket error occurs
    finally:
        s.close()  # Close the socket
    return ip  # Return the local IP address
    
# Network Settings
SERVER_IP = get_local_ip()  # Get the local IP address
SERVER_PORT = 5000  # Port for the server to listen on (any number above 1024, conventionally 5000)

# Setting buffer size to determine the maximum amount of data to be sent in one go
BUFFER_SIZE = 4096 

# CHACHA20 Settings
KEY_SIZE = 32  # Key size in bytes for CHACHA20
NONCE_SIZE = 16  # Nonce (Number Used Once) size in bytes for CHACHA20 (for added security)

# Generate a random key for CHACHA20 encryption
# NOTE: In a production environment, the keys would be stored. Could implement later.
CHACHA20_KEY = os.urandom(KEY_SIZE)
