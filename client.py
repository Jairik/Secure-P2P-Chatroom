''' Client Program to join the UDP broadcast, acting as a P2P client. '''

import socket
import threading
import sys
import config  # Importing to access constant keys/settings

# Connect client to server
print(f"Client started... connected to {config.SERVER_IP}:{config.SERVER_PORT}")

# Create, connect, and validate UDP socket constant IP and port in config.py
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create UDP socket
    client_socket.connect((config.SERVER_IP, config.SERVER_PORT))  # connect to server
    print(f"Successfully created socket to connect to server")
except socket.error as e:  # Socket creation error, exit
    print(f"Failed to create and create socket: {e}")
    print("Check firewall settings, try again later, or try running with sudo.")
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
            message, _ = client_socket.recvfrom(1024)  # Receive message from server
            # Add decryption methods (& signature verification) here
            print(f"Server: {message.decode('utf-8')}")
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
        message = input("You: ")
        if message.lower() == 'exit':
            print("Exiting chat...")
            break
        # Perform encryption methods (& signature) here
        client_socket.sendto(message.encode('utf-8'), (config.SERVER_IP, config.SERVER_PORT))
except KeyboardInterrupt:
    print("\nExiting chat...")


# Safely close the threads and socket, and exit the program
# TODO: Send message through socket to notify exit
client_socket.close()
