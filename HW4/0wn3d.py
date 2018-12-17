#!/usr/bin/python3
# coding: utf-8
from tqdm import tqdm
from itertools import product

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

def find_key_v1(before_pair, after_pair):
    """
    No brute force version

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

def find_key_v2(before_pair, after_pair):
    """
    brute force 2**12 versions

    before -- pair to encrypt
    after -- encrypted pair
    """
    delta = 0x9e3779b9
    key = [0]*4
    
    progress = tqdm(total=2**12)
    for k1, k3 in product(range(2**8), range(2**3)):
        progress.update()
        k3 = k3 << 5
        temp_key = [0, k1, 0, k3]
        if before_pair[1] == decrypt(temp_key, after_pair)[1]:
            for k0, k2 in product(range(2**8), range(2**3)):
                progress.update()
                k2 = k2 << 5
                key = temp_key
                key[0] = k0
                key[2] = k2
                if before_pair == decrypt(key, after_pair):
                    return key
    progress.update(2**11)
    return None

def find_key_v3(before_pair, after_pair):
    """
    brute force 2**22 versions

    before -- pair to encrypt
    after -- encrypted pair
    """
    delta = 0x9e3779b9
    iterations = 2**22
    for key in tqdm(product(range(2**8), range(2**8), range(2**3), range(2**3)), total=iterations):
        key = key[0], key[1], key[2] << 5, key[3] << 5
        if before_pair == decrypt(key, after_pair):
            return key
    return None

def get_keys(vulnerable_text):
    finders = [find_key_v1, find_key_v2, find_key_v3]
    keys = []
    after = hex2pair(vulnerable_text)
    for find_key in finders:
        for vladislav in integrity_check_suffix:
            before = bytes2pair(vladislav)
            key = find_key(before, after)
            if key is None:
                continue
            decrypted = decrypt(key, after)
            decrypted = pair2bytes(*decrypted)
            if decrypted == vladislav and all(map(lambda x: x == x & 0xff, key)):
                keys.append(key)
                return keys
    return keys

def _main():
    text = input("Input your encrypted text: ").encode()
    if len(text) == 0:
        raise NotImplementedError("Empty text")
    if len(text) % 16 != 0:
        raise NotImplementedError("text should be divisible by 8 (or 16 hex chars)")
    
    keys = get_keys(text[-16:])
    if len(keys) == 0:
        print('Cant hack any key. Possibly bad text!')
        return

    print('This can be key:')
    for key in keys:
        print('\t' + repr(key))
        print('\tWas decrypted by this key:')
        decrypted = b''
        for i in range(0, len(text) - 16, 16):
            pair = hex2pair(text[i: i + 16])
            dec = decrypt(key, pair)
            decrypted += pair2bytes(*dec)
        print('\t\t' + decrypted.decode())
    return

if __name__ == '__main__':
    _main()
