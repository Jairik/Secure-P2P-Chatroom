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
TODO: update known_peers to include public key for ED25519 signing (for each peer)
TODO: integrate encryption/decryption methods (pack_data, unpack_data) into client.py
----------------------------------------------------------------------------------
'''

# Show client connection information
print(f"Connected... multicast-group={config.MCAST_GRP}:{config.SERVER_PORT}")

''' Create UDP socket and bind to multicast group '''
try:
    # Create socket and allow multiple binds
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # create UDP socket
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable reuse of address
    client_socket.bind(('', config.SERVER_PORT))  # Bind to all interfaces on the port
    
    # Tell the socket to join the multicast group
    mreq = struct.pack("4sl", socket.inet_aton(config.MCAST_GRP), socket.INADDR_ANY)  # Creating a special packed structure to determine group
    client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)  # Set socket option to join specified multicast group
    
    print(f"Successfully established connection")
    
except socket.error as e:
    # Socket creation error, exit
    print(f"Failed to connect (socket error): {e}")
    sys.exit(1)
    
''' Get & validate username'''
username = input("Enter your username: ").strip()
if not username:
    print("Username cannot be empty. Exiting...")
    client_socket.close()
    sys.exit(1)
    
known_peers = set()  # declare set to store known peers (other clients)

# Declare listener for messages from other clients
def listen_for_messages() -> None:
    ''' Listen for incoming messages from other clients,  '''
    while True:
        try:
            
            # Receive message from the multicast group
            encrypted_message, _ = client_socket.recvfrom(1024)
            
            # Retrieve the cyphertext and signature from the payload
            encrypted_message_len = int.from_bytes(encrypted_message[:4], 'big')  # Get length of ciphertext
            encrypted_message = encrypted_message[4:4 + encrypted_message_len]  # Extract ciphertext
            signature = encrypted_message[4 + encrypted_message_len:]  # Extract signature            
            
            # 
            
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
        
def discovery_loop() -> None:
    ''' Declare discovery loop that checks for new peers, sending name and ed25519 public key '''
    while True:
        try:
            # Send a discovery message to the broadcast address
            raw_discovery_message = f"HEARTBEAT:{username}:{crypto_utils.get_ed_public_key()}"
            
            # Encrypt the discovery message
            encrypted_discovery_message = crypto_utils.pack_data_no_signature(raw_discovery_message)  # Encrypt the message
            
            # Send the encrypted discovery message to the multicast group
            client_socket.sendto(encrypted_discovery_message, (config.MCAST_GRP, config.SERVER_PORT))
            
            # Wait for a while before sending the next discovery message
            time.sleep(3)  # Broadcast every 3 seconds
            
        except Exception as e:
            print(f"Error in discovery loop: {e}")
            break

''' Assign each function to a thread '''
# Start a thread to listen for incoming messages
listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
listener_thread.start()

# Start a thread for the discovery loop
discovery_thread = threading.Thread(target=discovery_loop, daemon=True)
discovery_thread.start()

''' Main loop for sending messages'''
try:
    while True:
        # Get the raw message from the user
        raw_message = input(f"{username}: ")
        if raw_message.lower() == 'exit':
            print("Exiting chat...")
            break
        
        # Add username to message
        raw_formatted_message = f"{username}: {raw_message}"
        
        # Encryption methods & retrieve signature
        encrypted_message, signature = crypto_utils.pack_data(raw_formatted_message)
        
        # Combine encrypted message and signature into a single payload
        encrypted_message_len = len(encrypted_message).to_bytes(4, 'big')  # Get length of ciphertext
        payload = encrypted_message_len + encrypted_message + signature  # Combine length, ciphertext, and signature
        
        # Send the payload to the multicast group over UDP socket
        try:
            client_socket.sendto(payload, (config.MCAST_GRP, config.SERVER_PORT))
        except socket.error as e:
            print(f"Error sending payload: {e}")
            break
        
except KeyboardInterrupt:
    print("\nExiting chat...")

''' Safely cleanup the threads and sockes and exit '''
# Send exit message (no need to encrypt, just a notification)
exit_message = f"LEAVE: {username} has left the chat."
client_socket.sendto(exit_message.decode('utf-8'), (config.MCAST_GRP, config.SERVER_PORT))

# Safely cleanup threads and close the socket
threading.Event().wait(1)  # Safely wait for threads to finish
client_socket.close()