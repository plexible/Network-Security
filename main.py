from AES_Encryption import aes_encryption, generate_key
from AES_decryption import aes_decryption
from RSA_signiture import is_prime, generate_keys, RSA_signature, verify_message

def main():
    print("**************SENDER*****************")
    print()
    prime_first = input("Enter the first prime number: ")
    while(is_prime(int(prime_first))!=True):
        prime_first = input("Enter the first prime number: ")
    prime_second = input("Enter the second prime number: ")
    while(is_prime(int(prime_second))!=True or int(prime_first)>=int(prime_second)):
        prime_second = input("Enter the second prime number: ")
    PR, PU = generate_keys(83, 89)
    print("Public Key: ", PU)
    print("Private Key: ", PR)
    plainText = input("Enter the message: ")
    print()
    print("**************RSA Signiture*****************")
    print("Message: "+ plainText)
    signed_message = RSA_signature(plainText, PR)
    print()
    print("**************AES Encryption*****************")
    key = generate_key()
    print(f"Generated Key: {key}")
    encrypted_message = aes_encryption(signed_message, key)
    print()
    print(f"Message encrypted!\nEncrypted Message: {encrypted_message}")
    print()
    print("Message sent!")
    print()
    print("**************RECIEVER*****************")
    print()
    print("**************AES Decryption*****************")
    decrypted_message = aes_decryption(encrypted_message, key)
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

