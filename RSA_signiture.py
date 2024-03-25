#RSA Signiture Project

import random
from math import gcd
import base64
def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True


def generate_keys(p, q):
    if(is_prime(p) != True and is_prime(q) != True):
        return False
    n, z = (p * q), ((p-1) * (q-1))
    e = random.randint(1, z)
    while gcd(e, z) != 1:
          e = random.randint(2, z - 1)
    d = pow(e, -1, z)
    PR, PU = (d, n), (e, n)
    return PR, PU

def RSA_signature(plainText, PR):
    e, n = PR
    cipher = []

    for char in plainText:
        c = pow(ord(char), e, n)
        cipher.append(c)

    encoded_bytes = b"".join(c.to_bytes((n.bit_length() + 7) // 8, 'big') for c in cipher)

    encoded_cipher = base64.b64encode(encoded_bytes)
    signiture = encoded_cipher.decode('utf-8')
    signed_message = plainText + ";" + signiture
    print("Signiture: " + signiture)
    print("Signed message: "+ signed_message)
    print("Message signed!!!")
    return signed_message

def verify_message(signed_message, PU):
    message = signed_message.split(';')[0]
    print("Message: ",message)
    signiture = signed_message.split(';')[1]
    print("Signiture: ", signiture)
    d, n = PU
    plains = []
    plain = ""
    decoded_bytes = base64.b64decode(signiture)

    decrypted_cipher = []
    index = 0
    while index < len(decoded_bytes):
        num_bytes = int.from_bytes(decoded_bytes[index:index+((n.bit_length() + 7) // 8)], 'big')
        decrypted_cipher.append(num_bytes)
        index += (n.bit_length() + 7) // 8

    for c in decrypted_cipher:
        c = pow(c, d, n)
        plains.append(c)
        plain += chr(c)

    if(plain == message):
        print("Message verified")
        return True
    else:
        print("Not verified")
        return False

def main():
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
    print("**************Verification*****************")
    while True:
      key = input("Enter the private key (d, n), or enter '0' to exit: ")
      if key == "0":
          print("Exiting")
          break

      try:
          _d, _n = map(int, key.split(','))
          if verify_message(signed_message, (_d, _n)):
              break
          else:
              print("Message verification failed. Please try again.")
      except ValueError:
          print("Invalid input format. Please enter the private key in the format 'd, n'.")
#main()