#!/usr/bin/env python3
# coding: utf-8
import random
import sys
import os

integrity_check_suffix = [b'whatislo', b'vebabydo', b'nthurtme', b'donthurt', b'menomore']
MASK32 = 2**32

# байтовую строку в пару uint32 в big endian представлении
def bytes2pair(s):
    s = s[:4], s[4:]
    x = int.from_bytes(s[0], 'big')
    y = int.from_bytes(s[1], 'big')

    return x, y

# uint32 в байтовую строку в big endian представлении
def pair2bytes(x, y):
    s1 = bytes.fromhex(hex(x)[2:].zfill(8))
    s2 = bytes.fromhex(hex(y)[2:].zfill(8))

    return s1 + s2


def pair2str(x, y):
    return pair2bytes(x, y).decode()


def encrypt(key, pair):
    delta = 0x9e3779b9

    v0, v1 = pair
    
    v0 = (v0 + ((v1 << 4) ^ (key[0] << 4) ^ (v1 + delta) ^ (v1 >> 5) ^ (key[2] >> 5))) % MASK32
    v1 = (v1 + ((v0 << 4) ^ (key[1] << 4) ^ (v0 + delta) ^ (v0 >> 5) ^ (key[3] >> 5))) % MASK32
    
    return v0, v1

if __name__ == "__main__":
    plaintext = input("Input your text to encrypt: ").encode()

    if len(plaintext) % 8 != 0:
        raise NotImplementedError("Text should be divisible by 8")

    plaintext += random.choice(integrity_check_suffix)

    key = [int.from_bytes(os.urandom(1), 'big') for _ in range(4)]
    print("Generating key: %s" % repr(key))

    ciphertext = []
    for i in range(0, len(plaintext), 8):
        block = plaintext[i: i + 8]
        ciphertext.extend(encrypt(key, bytes2pair(block)))

    ciphertext = b''.join(
        pair2bytes(ciphertext[i], ciphertext[i + 1]) for i in range(0, len(ciphertext), 2)
    )

    # В случае старого python можно использовать binascii.hexlify() вместо str.hex()
    print("Ciphertext: %s" % ciphertext.hex())
