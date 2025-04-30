''' Client Program to join the UDP broadcast, acting as a P2P client. '''

import socket
import threading
import sys
import time
import struct  # For packing and unpacking binary data and allowing multicasting groups
import config  # Access constant keys/settings
import errno  # For error handling
import crypto_utils  # For encryption/decryption methods
import pickle  # For serializing and deserializing objects


# Show client connection information
print(f"Connected... multicast-group={config.MCAST_GRP}:{config.MCAST_PORT}")

''' Create UDP socket and bind to multicast group '''
try:
    # Create socket and allow multiple binds
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # create UDP socket
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable reuse of address
    client_socket.bind(('', config.MCAST_PORT))  # Bind to all interfaces on the port
    
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
    
known_peers = dict()  # Declare dictionary to map known peer usernames to public keys for message signatures (verification)

# Declare listener for messages from other clients
def listen_for_messages() -> None:
    ''' Listen for incoming messages from other clients,  '''
    while True:
        try:
            # Receive message from the multicast group
            payload, _ = client_socket.recvfrom(config.BUFFER_SIZE)
            
            # Retrieve the message type, cyphertext, & signature (or public key) from the payload with pickle
            message_type, encrypted_message, signature = pickle.loads(payload)
            
            ''' Determine behavior based on unencrypted message type '''
            # CHAT: Unencrypt the payload, verify signature, and print the message
            if message_type == "CHAT":
                # Decrypt the message and print
                raw_received_message = crypto_utils.unpack_data(encrypted_message)
                if not raw_received_message.startswith(username + ": "):  # Ignoring own messages
                    pass # NOTE: will determine signatures verification once public keys are added to known_peers
                
            # JOIN: Add the new username and public key to the known peers list
            elif message_type == "JOIN":
                # Decrypt the message to get the username and public key
                decrypted_message = crypto_utils.unpack_data(encrypted_message)
                decrypted_public_key = crypto_utils.unpack_data(signature)
                new_username = decrypted_message.split(':', 1)[1]  # Extract the username from the message
                
                # Add the new peer to list of known peers
                if new_username not in known_peers:
                    known_peers[new_username] = decrypted_public_key  # Store the public key in dict for signing
                    print(f"Welcome {new_username} to the chat!")
                        
            # LEAVE: Remove the username and public key from the known peers list
            elif message_type == "LEAVE":
                # Decrypt the username 
                decrypted_username = crypto_utils.unpack_data(encrypted_message)
                print(f"{decrypted_username} has left the chat.")
                
                # Remove the username-public key pair from the known peers list
                if decrypted_username in known_peers:
                    try:
                        del known_peers[decrypted_username]
                    except KeyError:
                        pass  # Shouldn't ever happen, but catch common KeyError just in case
                
            else:  # Invalid Message Type
                print(f"Unknown message type: {message_type}")
                continue
                    
        except Exception as e:
            if e.errno == errno.EBADF:
                pass  # Ignore bad file descriptor error (socket closed)
            else:
                print(f"Error receiving message: {e}")
                break
        
def discovery_loop() -> None:
    ''' Declare discovery loop that checks for new peers, sending encrypted name and ed25519 public key '''
    while True:
        try:
            # Encrypt the username and public key
            encrypted_discovery_username = crypto_utils.pack_data({username})
            encrypted_ed_public_key = crypto_utils.pack_data(crypto_utils.get_ed_public_key())
            
            # Combine message type, encrypted username, and encrypted public key into a single payload with pickle
            payload = pickle.dumps(("JOIN", encrypted_discovery_username, encrypted_ed_public_key))
            
            # Send the encrypted discovery message to the multicast group
            client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))
            
            # Wait for a while (3 seconds) before sending the next discovery message
            time.sleep(3)
            
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
        
        # Combine message type, encrypted message, and signature into a single payload with pickle
        payload = pickle.dumps(("CHAT", encrypted_message, signature))
        
        # Send the payload to the multicast group over UDP socket
        try:
            client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))
        except socket.error as e:
            print(f"Error sending payload: {e}")
            break
        
except KeyboardInterrupt:
    print("\nExiting chat...")

''' Safely cleanup the threads and sockets '''
# Send exit message (no need to encrypt, just a notification)
payload = pickle.dumps(("LEAVE", {username}.encode('utf-8'), None))
client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))

# Safely cleanup threads and close the socket
threading.Event().wait(1)  # Safely wait for threads to finish
client_socket.close()