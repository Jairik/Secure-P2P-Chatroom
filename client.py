''' Client Program to join the UDP broadcast, acting as a P2P client. '''

import socket
import threading
import sys
import config  # Importing to access constant keys/settings

# Connect client to server
print(f"Client started... host={config.SERVER_IP}:{config.SERVER_PORT}")

# Create, connect, and validate UDP socket constant IP and port in config.py
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create UDP socket
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable reuse of address
    client_socket.bind(('', config.SERVER_PORT))  # Bind to all interfaces on the port
    print(f"Successfully created socket to connect to server")
except socket.error as e:  # Socket creation error, exit
    print(f"Failed to create and create socket: {e}")
    sys.exit(1)
    
# Get & validate the user's username
username = input("Enter your username: ")
if not username:
    print("Username cannot be empty. Exiting...")
    client_socket.close()
    sys.exit(1)

# Declare listener for messages from other clients
def listen_for_messages():
    while True:
        try:
            message, address = client_socket.recvfrom(1024)  # Receive message from server
            decoded_message = message.decode('utf-8')
            # Add decryption methods (& signature verification) here
            if not decoded_message.startswith(username + ": "):  # Ignore messages from self
                print(f"Server: {decoded_message}")  # TODO: Get the sender's username from the message
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start a thread to listen for incoming messages
listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
listener_thread.start()

# Main loop to send messages to the server
# TODO: when connected, send message that the user has joined the chat
try:
    while True:
        message = input(f"{username}: ")
        if message.lower() == 'exit':
            print("Exiting chat...")
            break
        # Add username to message
        message = f"{username}: {message}"
        # Perform encryption methods (& signature) here
        try:
            client_socket.sendto(message.encode('utf-8'), (config.GLOBAL_BROADCAST_IP, config.SERVER_PORT))
        except socket.error as e:
            print(f"Error sending message: {e}")
            break
except KeyboardInterrupt:
    print("\nExiting chat...")


# Safely close the threads and socket, and exit the program
# TODO: Send message through socket to notify exit
client_socket.close()
