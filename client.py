''' Client Program to join the UDP broadcast, acting as a P2P client. '''

import socket
import threading
import sys
import time
import struct  # For packing and unpacking binary data and allowing multicasting groups
import config  # Access constant keys/settings
import errno  # For error handling
import crypto_utils  # For encryption/decryption methods (not implemented yet)

'''
----------------------------------------------------------------------------------
TODO: update known_peers to include public key for ED25519 signing (for each peer
----------------------------------------------------------------------------------
'''

# Show client connection information
print(f"Client started... multicast-group={config.MCAST_GRP}:{config.SERVER_PORT}")

# Create, connect, and validate UDP socket constant IP and port in config.py
try:
    # Create socket and allow multiple binds
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # create UDP socket
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable reuse of address
    client_socket.bind(('', config.SERVER_PORT))  # Bind to all interfaces on the port
    
    # Tell the socket to join the multicast group
    mreq = struct.pack("4sl", socket.inet_aton(config.MCAST_GRP), socket.INADDR_ANY)  # Creating a special packed structure to determine group
    client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)  # Set socket option to join specified multicast group
    
    print(f"Successfully established connection")
except socket.error as e:  # Socket creation error, exit
    print(f"Failed to connect (socket error): {e}")
    sys.exit(1)
    
# Get & validate the user's username
username = input("Enter your username: ").strip()
if not username:
    print("Username cannot be empty. Exiting...")
    client_socket.close()
    sys.exit(1)
    
known_peers = set()  # store known peers (other clients)

# Declare listener for messages from other clients
def listen_for_messages():
    while True:
        try:
            message, address = client_socket.recvfrom(1024)  # Receive message from server
            decoded_message = message.decode('utf-8')  # Retrieve decoded message
            sender_ip, _ = address # Derive the sender ip from address
            
            # !! NOTE: Add decryption methods (& signature) here (can be wrapped in unpack_data())
            
            
            # Check for new peers
            if decoded_message.startswith('HEARTBEAT:'):  # Check if the message is encrypted
                    new_username = decoded_message.split(':', 1)[1]  # Extract the username from the message
                    # Add the new peer to list of known peers
                    if new_username not in known_peers:
                        known_peers.add(new_username)
                        print(f"Welcome {new_username} to the chat!")
            elif not decoded_message.startswith(username + ": "):  # Ignore own messages
                print(f"\n{decoded_message}")  # Print the message
            else:  # Message is from self, continue
                continue
                    
        except Exception as e:
            if e.errno == errno.EBADF:
                pass  # Ignore bad file descriptor error (socket closed)
            else:
                print(f"Error receiving message: {e}")
                break
        
# Declare discovery loop that checks for new peers
def discovery_loop():
    while True:
        try:
            # Send a discovery message to the broadcast address
            discovery_message = f"HEARTBEAT:{username}"            
            client_socket.sendto(discovery_message.encode('utf-8'), (config.MCAST_GRP, config.SERVER_PORT))
            # Wait for a while before sending the next discovery message
            time.sleep(3)  # Broadcast every 3 seconds
        except Exception as e:
            print(f"Error in discovery loop: {e}")
            break

# Start a thread to listen for incoming messages
listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
listener_thread.start()

# Start a thread for the discovery loop
discovery_thread = threading.Thread(target=discovery_loop, daemon=True)
discovery_thread.start()

# Main loop to send messages to the server
try:
    while True:
        message = input(f"{username}: ")
        if message.lower() == 'exit':
            print("Exiting chat...")
            break
        # Add username to message
        message = f"{username}: {message}"
        
        # !! NOTE: Add encryption methods (& signature) here (can be wrapped in pack_data())
            
            
        try:
            client_socket.sendto(message.encode('utf-8'), (config.MCAST_GRP, config.SERVER_PORT))
        except socket.error as e:
            print(f"Error sending message: {e}")
            break
except KeyboardInterrupt:
    print("\nExiting chat...")


# Safely close the threads and socket, and exit the program
# TODO: Send message through socket to notify exit
client_socket.close()
threading.Event().wait(1)  # Safely wait for threads to finish
