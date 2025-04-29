''' Wrapper Module for clean encryption, decryption, and message signatures in client.py '''

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import config

''' Generating keys and cipher objects for encryption and signing '''
chacha_private_key = ChaCha20Poly1305.generate_key()  # Generate a secret key for encryption (32 bytes)
chacha_cipher = ChaCha20Poly1305(chacha_private_key)  # Add key to a CHACHA20 cipher object
ed_private_key = Ed25519PrivateKey.generate()  # Generate a private key for signing (32 bytes)
nonce = None


def pack_data(data: str, associated_data: str = None) -> tuple:
    ''' Encrypt and add signature to data before sending 
    Returns the encrypted data and signature as tuple of ciphertext bytes '''
    # Redeclare nonce for each message (to prevent nonce reuse)
    nonce = os.urandom(config.NONCE_SIZE)
    ct = chacha_cipher.encrypt(nonce, data, associated_data)  # Get ciphertext
    signature = ed_private_key.sign(data)  # Get signature
    return ct, signature  # Return ciphertext and signature as tuple

def pack_data_no_signature(data: str, associated_data: str = None) -> bytes:
    ''' Encrypt data before sending without signature 
    Returns the encrypted data as bytes '''
    # Redeclare nonce for each message (to prevent nonce reuse)
    nonce = os.urandom(config.NONCE_SIZE)
    ct = chacha_cipher.encrypt(nonce, data, associated_data)  # Get ciphertext
    return ct  # Return ciphertext as bytes
    
def unpack_data(ct: bytes, associated_data: str = None) -> str:
    ''' Decrypt and authenticate data after receiving
    Returns the decrypted data and signature as a string '''
    try:
        raw_data = chacha_cipher.decrypt(nonce, ct, associated_data)  # Decrypt the ciphertext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None  # Decryption failed, return None
    return raw_data.decode('utf-8')  # Return the decrypted data as a string

def unpack_data_no_signature(ct: bytes, associated_data: str = None) -> str:
    ''' Decrypt data after receiving without signature 
    Returns the decrypted data as a string '''
    try:
        raw_data = chacha_cipher.decrypt(nonce, ct, associated_data)  # Decrypt the ciphertext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None  # Decryption failed, return None
    return raw_data.decode('utf-8')  # Return the decrypted data as a string
    
def get_ed_public_key() -> bytes:
    ''' Helper function to get public key of client for signing '''
    return ed_private_key.public_key().public_bytes()

def verify_signature(public_key_raw: bytes, signature: bytes, data: str) -> bool:
    ''' Helper function to verify the signature of the data using the public key '''
    public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)  # Convert raw bytes to public key object
    try:
        public_key.verify(signature, data)  # Will raise an error if signature is invalid
        return True  # Signature is valid
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False  # Signature is invalid