#!/usr/bin/env python3
# coding: utf-8
import sys
import os

integrity_check_suffix = [b'whatislo', b'vebabydo', b'nthurtme', b'donthurt', b'menomore']
MASK32 = 2**32

# uint32 в байтовую строку в big endian представлении
def pair2bytes(x, y):
    s1 = bytes.fromhex(hex(x)[2:])
    s2 = bytes.fromhex(hex(y)[2:])

    return s1 + s2

def pair2str(x, y):
    return pair2bytes(x, y).decode()

# перевести hex-строку в пару uint32 в big endian представлении
def hex2pair(s):
    s = s[:8], s[8: 16]
    x = int(s[0], 16)
    y = int(s[1], 16)

    return x, y

def decrypt(key, pair):
    delta = 0x9e3779b9

    v0, v1 = pair

    v1 = (v1 - ((v0 << 4) ^ (key[1] << 4) ^ (v0 + delta) ^ (v0 >> 5) ^ (key[3] >> 5))) % MASK32
    v0 = (v0 - ((v1 << 4) ^ (key[0] << 4) ^ (v1 + delta) ^ (v1 >> 5) ^ (key[2] >> 5))) % MASK32

    return v0 % MASK32, v1 % MASK32


if __name__ == "__main__":
    key = input("Input your key (four uint8, e.g. 14, 72, 55, 88): ")
    key = [int(n) for n in key.strip().split(', ')]

    if len(key) != 4 or any(map(lambda x: x != x & 0xff, key)):
        raise NotImplementedError("Key should consist of four uint8 numbers")

    ciphertext = input("Input your text to decrypt in hex: ")

    if len(ciphertext) % 16 != 0:
        print("")
        print(key)
        print(ciphertext, len(ciphertext))
        raise NotImplementedError("Ciphertext should be divisible by 8 (or 16 hex chars)")

    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        pair = hex2pair(ciphertext[i: i + 16])
        dec = decrypt(key, pair)
        plaintext += pair2bytes(*dec)

    assert plaintext[-8:] in integrity_check_suffix, "Something went wrong :("

    print(plaintext[:-8])
