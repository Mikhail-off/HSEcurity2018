#!/usr/bin/python3
# coding: utf-8

integrity_check_suffix = [b'whatislo', b'vebabydo', b'nthurtme', b'donthurt', b'menomore']
MASK32 = 1 << 32

def pair2bytes(x, y):
    s1 = bytes.fromhex(hex(x)[2:])
    s2 = bytes.fromhex(hex(y)[2:])
    return s1 + s2

def pair2str(x, y):
    return pair2bytes(x, y).decode()

def hex2pair(s):
    s = s[:8], s[8: 16]
    x = int(s[0], 16)
    y = int(s[1], 16)
    return x, y

def bytes2pair(s):
    s = s[:4], s[4:]
    x = int.from_bytes(s[0], 'big')
    y = int.from_bytes(s[1], 'big')

    return x, y

def decrypt(key, pair):
    delta = 0x9e3779b9

    v0, v1 = pair

    v1 = (v1 - ((v0 << 4) ^ (key[1] << 4) ^ (v0 + delta) ^ (v0 >> 5) ^ (key[3] >> 5))) % MASK32
    v0 = (v0 - ((v1 << 4) ^ (key[0] << 4) ^ (v1 + delta) ^ (v1 >> 5) ^ (key[2] >> 5))) % MASK32

    return v0 % MASK32, v1 % MASK32

def find_key(before_pair, after_pair):
    """
    before -- pair to encrypt
    after -- encrypted pair
    """
    delta = 0x9e3779b9
    key = [0]*4
    
    b0, b1 = before_pair
    a0, a1 = after_pair
    
    xored_k0_k2 = ((a0 - b0) % MASK32) ^ (b1 << 4) ^ (b1 + delta) ^ (b1 >> 5)
    xored_k1_k3 = ((a1 - b1) % MASK32) ^ (a0 << 4) ^ (a0 + delta) ^ (a0 >> 5)
    xored_k0_k2, xored_k1_k3 = xored_k0_k2 % MASK32, xored_k1_k3 % MASK32 

    key[0] = xored_k0_k2 >> 4
    key[1] = xored_k1_k3 >> 4
    key[2] = ((key[0] << 4) ^ xored_k0_k2) << 5
    key[3] = ((key[1] << 4) ^ xored_k1_k3) << 5
    return key

def get_keys(vulnerable_text):
    keys = []
    after = hex2pair(vulnerable_text)
    for vladislav in integrity_check_suffix:
        before = bytes2pair(vladislav)
        key = find_key(before, after)
        decrypted = decrypt(key, after)
        decrypted = pair2bytes(*decrypted)
        if decrypted == vladislav and all(map(lambda x: x == x & 0xff, key)):
            keys.append(key)
    return keys

def _main():
    plaintext = input("Input your encrypted text: ").encode()
    if len(plaintext) % 16 != 0:
        raise NotImplementedError("Ciphertext should be divisible by 8 (or 16 hex chars)")
    
    keys = get_keys(plaintext[-16:])
    print('This can be key:')
    for key in keys:
        print('\t' + repr(key))
    return

if __name__ == '__main__':
    _main()
