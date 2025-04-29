''' Wrapper Module for clean encryption, decryption, and message signatures for clients '''

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def pack_data():
    ''' Package and encrypt data for sending '''
    
def unpack_data():
    ''' Unpack and decrypt data after receiving '''