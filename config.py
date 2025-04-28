''' Constants such as port numbers, IP addresses, and keys '''

import os  # For random key generation
import socket  # For determining the local IP address
import psutil  # For retreiving the broadcasecast address
import ipaddress

# Get the broadcast address
def get_ip_addresses():
    """Get the broadcast address and the local IP address of the local network."""
    # Get all network interfaces and their addresses
    addrs = psutil.net_if_addrs()
    
    # Loop through each interaface and its addresses (finds the first private one)
    for iface_name, iface_addresses in addrs.items():
        for addr in iface_addresses:
            if addr.family == socket.AF_INET:  # Only consider IPv4 addresses
                ip = addr.address
                netmask = addr.netmask
                # Only proceed if it's a private (local) IP address
                if ip.startswith('192.') or ip.startswith('10.') or ip.startswith('172.'):
                    ip_network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    broadcast_ip = str(ip_network.broadcast_address)
                    print(f"Found local IP: {ip}, Broadcast IP: {broadcast_ip}")
                    return ip, broadcast_ip  # Return the local IP and broadcast address
    
    print("No suitable network interface found, attempting to run default.")
    return None, '255.255.255.255'  # Fallback
    
# Network Settings
SERVER_IP, GLOBAL_BROADCAST_IP = get_ip_addresses()  # Get the local IP and global broadcast address
SERVER_PORT = 5000  # Port for the server to listen on (any number above 1024, conventionally 5000)

# Setting buffer size to determine the maximum amount of data to be sent in one go
BUFFER_SIZE = 4096 

# CHACHA20 Settings
KEY_SIZE = 32  # Key size in bytes for CHACHA20
NONCE_SIZE = 16  # Nonce (Number Used Once) size in bytes for CHACHA20 (for added security)

# Generate a random key for CHACHA20 encryption
# NOTE: In a production environment, the keys would be stored. Could implement later.
CHACHA20_KEY = os.urandom(KEY_SIZE)
