''' Wrapper Module for clean encryption, decryption, and message signatures in client.py '''

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import config
from typing import Union, Tuple  # For type hinting

''' Generating keys and cipher objects for encryption and signing '''
chacha_cipher = ChaCha20Poly1305(config.SHARED_CHACHA20_KEY)  # Add key to a CHACHA20 cipher object
ed_private_key = Ed25519PrivateKey.generate()  # Generate a private key for signing (32 bytes)

def pack_data(data: bytes, associated_data: bytes = b'', sign: bool = True, nonce: bytes = None) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
    ''' Encrypt and add signature to data before sending 
    Returns the encrypted data, nonce, and signature (optionally) as tuple of ciphertext bytes '''
    if nonce == None: nonce = os.urandom(config.NONCE_SIZE)  # Redeclare nonce for each message (to prevent nonce reuse)
    ct = chacha_cipher.encrypt(nonce, data, associated_data)  # Get ciphertext
    if sign:  # If signing, return cyphertext and signature
        signature = ed_private_key.sign(data)  # Get signature
        return ct, nonce, signature  # Return ciphertext and signature as tuple
    else:  # If not signing, return only ciphertext
        return ct, nonce  # Return only ciphertext as bytes

def unpack_data(ct: bytes, nonce: bytes, associated_data: str = b'', isKey: bool = False) -> Union[str, bytes]:
    ''' Decrypt and authenticate data after receiving
    Returns the decrypted data and signature as a string '''
    try:
        raw_data = chacha_cipher.decrypt(nonce, ct, associated_data)  # Decrypt the ciphertext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None  # Decryption failed, return None
    if not isKey:
        raw_data: str = raw_data.decode('utf-8')  # Decode bytes to string if not a key
    return raw_data

def get_ed_public_key() -> bytes:
    ''' Helper function to get public key of client for signing '''
    return ed_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,  # Raw bytes encoding
        format=serialization.PublicFormat.Raw  # Raw public key format
    )

def verify_signature(public_key_raw: bytes, signature: bytes, data: str) -> bool:
    ''' Helper function to verify the signature of the data using the public key '''
    public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)  # Convert raw bytes to public key object
    try:
        public_key.verify(signature, data)  # Will raise an error if signature is invalid
        return True  # Signature is valid
    except Exception as e:
        # print(f"Signature verification failed: {e}")  # Custom handling could be used for this
        return False  # Signature is invalid