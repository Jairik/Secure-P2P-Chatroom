''' Client Program to participate in the UDP multicast, acting as a P2P client. '''

import socket
import threading
import sys
import time
import struct  # For packing and unpacking binary data and allowing multicasting groups
import errno  # For error handling
import pickle  # For serializing and deserializing objects

import config  # Access constant keys/settings
import crypto_utils  # For encryption/decryption methods

import dearpygui.dearpygui as dpg

def switch_to_messaging_window(newWidth = 600, newHeight = 600):
    global username
        
    dpg.hide_item("username-submission")
    dpg.show_item("messaging")

    dpg.set_value("my-username", "my username: " + username)

    dpg.set_viewport_width(newWidth)
    dpg.set_viewport_height(newHeight)
    dpg.set_item_width("Window", newWidth)
    dpg.set_item_height("Window", newHeight)
        

def create_ui():
    
    dpg.create_viewport(title='Messaging App', width=600, height=300)

    with dpg.item_handler_registry(tag="submit-name-handler") as handler:
        dpg.add_item_clicked_handler(callback=on_name_submit)
    with dpg.item_handler_registry(tag="submit-message-handler") as handler:
            dpg.add_item_clicked_handler(callback=on_message_submit)

    with dpg.window(tag="Window", width=600, height=300):
        with dpg.group(tag="username-submission"):
            # Show client connection information
            dpg.add_text(f"Connected... multicast-group={config.MCAST_GRP}:{config.MCAST_PORT}")
            dpg.add_text(tag="conn-status")
            dpg.add_text("Enter Username:")
            dpg.add_text(tag="username-help")
            dpg.add_input_text(tag="input-username")
            dpg.add_button(label="Submit", tag="submit-name")
        with dpg.group(tag="messaging", show=False):
            dpg.add_text(tag="my-username")
            with dpg.child_window(tag="msg-log", width=-1, height=400, autosize_x=True):
                pass
            dpg.add_input_text(tag="msg-input", width=200, pos=(50, 500))
            dpg.add_button(label="Send", tag="send-msg", pos=(300, 500))

    dpg.bind_item_handler_registry("submit-name", "submit-name-handler")
    dpg.bind_item_handler_registry("send-msg", "submit-message-handler")

    dpg.set_exit_callback(send_leave_message)

    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window("Window", True)
    dpg.start_dearpygui()
    dpg.destroy_context()
    
def create_udp_socket():
    global client_socket
    ''' Create UDP socket and bind to multicast group '''
    try:
        # Create socket and allow multiple binds
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # create UDP socket
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable reuse of address
        client_socket.bind(('', config.MCAST_PORT))  # Bind to all interfaces on the port
        
        # Tell the socket to join the multicast group
        mreq = struct.pack("4sl", socket.inet_aton(config.MCAST_GRP), socket.INADDR_ANY)  # Creating a special packed structure to determine group
        client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)  # Set socket option to join specified multicast group
        
        dpg.set_value("conn-status", f"Connection successfully established")
    
    except socket.error as e:
        # Socket creation error, exit
        dpg.set_value("conn-status", f"Failed to connect (socket error): {e}")

def on_name_submit():
    global listener_thread, discovery_thread, username
    temp_username = dpg.get_value("input-username")
    if temp_username != "":
        username = temp_username
        switch_to_messaging_window()
        listener_thread.start()
        discovery_thread.start()
    else:
        dpg.set_value("username-help", "Username cannot be empty")

# Declare listener for messages from other clients
def listen_for_messages() -> None:
    global client_socket
    ''' Listen for incoming messages from other clients, handling based on received message type '''
    while True:
        try:
            # Receive message from the multicast group
            payload, _ = client_socket.recvfrom(config.BUFFER_SIZE)
            
            # Retrieve the message type, cyphertext, nonce, signature or public key, and 
            # public key nonce (if applicable) from the payload with pickle
            message_type, encrypted_message, nonce, signature, sig_nonce = pickle.loads(payload)
            
            ''' Determine behavior based on unencrypted message type '''
            # CHAT: Unencrypt the payload, verify signature, and print the message
            if message_type == "CHAT":
                # Decrypt the message and print
                raw_received_message = crypto_utils.unpack_data(encrypted_message, nonce)
                if not raw_received_message.startswith(username + ": "):  # Ignoring own messages
                    # Verify the signature using the public key of the sender
                    sender_username = raw_received_message.split(": ")[0]
                    
                    # If the username is not yet stored, client hasn't caught name from discovery loop yet, so skip
                    if sender_username not in known_peers:
                        continue
                    
                    # Compare the sent signature with the stored public key of the sender
                    elif crypto_utils.verify_signature(known_peers[sender_username], signature, raw_received_message.encode('utf-8')):
                        log_message(f"{raw_received_message}")  # Print the message if signature is valid
                    
                    # Signature verification failed. 
                    else:
                        continue  # Custom handling could be added for this
                
            # JOIN: Add the new username and public key to the known peers list
            elif message_type == "JOIN":
                # Decrypt the message to get the username and public key
                new_username = crypto_utils.unpack_data(encrypted_message, nonce)
                decrypted_public_key = crypto_utils.unpack_data(signature, sig_nonce, isKey=True)
                
                # Add the new peer to list of known peers
                if new_username not in known_peers:
                    known_peers[new_username] = decrypted_public_key  # Store the public key in dict for signing
                    log_message(f"Welcome {new_username} to the chat!")
                        
            # LEAVE: Remove the username and public key from the known peers list
            elif message_type == "LEAVE":
                # Decrypt the username 
                decrypted_username = encrypted_message.decode('utf-8')
                log_message(f"{decrypted_username} has left the chat.")
                
                # Remove the username-public key pair from the known peers list
                if decrypted_username in known_peers:
                    try:
                        del known_peers[decrypted_username]
                    except KeyError:
                        pass  # Shouldn't ever happen, but catch common KeyError just in case
                
            else:  # Invalid Message Type
                log_message(f"Unknown message type: {message_type}")
                continue
                    
        except OSError as e:
            if e.errno == errno.EBADF:
                pass  # Ignore bad file descriptor error (socket closed)
        except Exception as e:
            log_message(f"Error receiving message: {e}")
            break
        
def discovery_loop() -> None:
    global client_socket
    ''' Declare discovery loop that checks for new peers, sending encrypted name and ed25519 public key '''
    while True:
        try:
            # Encrypt the username and public key
            encrypted_discovery_username, username_nonce = crypto_utils.pack_data(username.encode('utf-8'), sign=False)  # No signature
            encrypted_ed_public_key, public_key_nonce = crypto_utils.pack_data(crypto_utils.get_ed_public_key(), sign=False)  # No signature
            
            # Combine message type, encrypted username, and encrypted public key into a single payload with pickle
            payload = pickle.dumps(("JOIN", encrypted_discovery_username, username_nonce, encrypted_ed_public_key, public_key_nonce))
            
            # Send the encrypted discovery message to the multicast group
            client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))
            
            # Wait for a while (3 seconds) before sending the next discovery message
            time.sleep(3)
            
        except Exception as e:
            print(f"Error in discovery loop: {e}")
            break

def log_message(message):
    dpg.add_text(message, parent="msg-log")

def on_message_submit():
    # Add username to message
    raw_message = dpg.get_value("msg-input")
    dpg.set_value("msg-input", "")

    if(raw_message != ""):
        raw_formatted_message = f"{username}: {raw_message}"
        log_message(raw_formatted_message)
        # Encryption methods & retrieve signature
        encrypted_message, message_nonce, signature = crypto_utils.pack_data(raw_formatted_message.encode('utf-8'))
        
        # Combine message type, encrypted message, and signature into a single payload with pickle
        payload = pickle.dumps(("CHAT", encrypted_message, message_nonce, signature, config.NULL_BYTE))
        
        # Send the payload to the multicast group over UDP socket
        try:
            client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))
        except socket.error as e:
            print(f"Error sending payload: {e}")

def send_leave_message():
    threading.Event().wait(1)  # Safely wait for threads to finish
    payload = pickle.dumps(("LEAVE", username.encode('utf-8'), config.NULL_BYTE, config.NULL_BYTE, config.NULL_BYTE))
    client_socket.sendto(payload, (config.MCAST_GRP, config.MCAST_PORT))
    client_socket.close()
    

            
dpg.create_context()

client_socket = None
username = ""
known_peers = dict()  # Declare dictionary to map known peer usernames to public keys for message signatures (verification)

ui_thread = threading.Thread(target=create_ui)
listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
discovery_thread = threading.Thread(target=discovery_loop, daemon=True)

ui_thread.start()
create_udp_socket()