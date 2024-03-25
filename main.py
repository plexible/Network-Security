import base64
from AES_Encryption import aes_encryption, list_base64_encode
from AES_decryption import aes_decryption
from Diffie_Hellman import generate_dh_parameters, generate_keypair, generate_shared_key
from RSA_signiture import RSA_signature, generate_keys, is_prime, verify_message


def main():
    print("**************SENDER*****************")
    print()
    prime_first = input("Enter the first prime number: ")
    while(is_prime(int(prime_first))!=True):
        prime_first = input("Enter the first prime number: ")
    prime_second = input("Enter the second prime number: ")
    while(is_prime(int(prime_second))!=True or int(prime_first)>=int(prime_second)):
        prime_second = input("Enter the second prime number: ")
    PR, PU = generate_keys(int(prime_first), int(prime_first))
    print("Public Key: ", PU)
    print("Private Key: ", PR)
    plainText = input("Enter the message: ")
    print()
    print("**************RSA Signiture*****************")
    print("Message: "+ plainText)
    signed_message = RSA_signature(plainText, PR)
    print()
    print("**************AES Encryption*****************")
    parameters = generate_dh_parameters()
    bob_private_key, bob_public_key = generate_keypair(parameters)
    alice_private_key, alice_public_key = generate_keypair(parameters)
    bob_shared_key = generate_shared_key(bob_private_key, alice_public_key)
    alice_shared_key = generate_shared_key(alice_private_key, bob_public_key)
    print(f"Generated Bob Shared Key: {base64.b64encode(bob_shared_key).decode()}")
    encrypted_message = aes_encryption(signed_message, bob_shared_key)
    print()
    print(f"Message encrypted!\nEncrypted Message: {encrypted_message}")
    print()
    print("Message sent!")
    print()
    print("**************RECIEVER*****************")
    print()
    print("**************AES Decryption*****************")
    print(f"Generated Alice Shared Key: {base64.b64encode(alice_shared_key).decode()}")
    decrypted_message = aes_decryption(encrypted_message, alice_shared_key)
    print(f"Message decrypted!\nDecrypted Message: {decrypted_message}")
    print()
    print("**************Verification*****************")
    while True:
        key = input("Enter the private key (d, n), or enter '0' to exit: ")
        if key == "0":
            print("Exiting")
            break
        try:
            _d, _n = map(int, key.split(','))
            if verify_message(decrypted_message, (_d, _n)):
                break
            else:
                print("Message verification failed. Please try again.")
        except ValueError:
            print("Invalid input format. Please enter the private key in the format 'd, n'.")
main()