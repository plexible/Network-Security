from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from AES_Encryption import aes_encryption
from AES_decryption import aes_decryption
import os

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key[:32]