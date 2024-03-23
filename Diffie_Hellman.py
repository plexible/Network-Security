import random
from RSA_signiture import is_prime

def generate_prime_number():
    # Asal sayı üretimi için basit bir yöntem
    while True:
        num = random.randint(100, 1000)
        if is_prime(num):
            return num

