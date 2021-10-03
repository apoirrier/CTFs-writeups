# Double DES

> I wanted an encryption service that's more secure than regular DES, but not as slow as 3DES...
> 
> The flag is not in standard format.
>
> nc mercury.picoctf.net 5958

Attached is the following Python file:

```python
#!/usr/bin/python3 -u
from Crypto.Cipher import DES
import binascii
import itertools
import random
import string


def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

def generate_key():
    return pad("".join(random.choice(string.digits) for _ in range(6)))


FLAG = open("flag").read().rstrip()
KEY1 = generate_key()
KEY2 = generate_key()


def get_input():
    try:
        res = binascii.unhexlify(input("What data would you like to encrypt? ").rstrip()).decode()
    except:
        res = None
    return res

def double_encrypt(m):
    msg = pad(m)

    cipher1 = DES.new(KEY1, DES.MODE_ECB)
    enc_msg = cipher1.encrypt(msg)
    cipher2 = DES.new(KEY2, DES.MODE_ECB)
    return binascii.hexlify(cipher2.encrypt(enc_msg)).decode()


print("Here is the flag:")
print(double_encrypt(FLAG))

while True:
    inputs = get_input()
    if inputs:
        print(double_encrypt(inputs))
    else:
        print("Invalid input.")
```

## Description

We get the flag encrypted using Double DES, meaning that given two DES keys `k1` and `k2`, a message `m` is encrypted with `DES(k1, DES(k2, m))`.

In this instance, keys are much more simple and are composed of 6 random digits plus 2 spaces, so the key space is relatively small.

Moreover we get access to an encryption oracle: we get the encryption of any message we want to provide.

## Solution

Double DES is not more secure than simple DES because of the attack by the middle.

Indeed, given a key space `K` for simple DES, one can compute every encryption of a message `m` under a key `k`, and every decryption of a ciphertext `c` under `k`.
This has complexity `O(|K|)`.

Therefore, if some attacker knows that `c = Double-DES(m)` (without knowing the keys), it can compute the above sets for `m` and `c` and try to find an element of the intersection in both sets.
Such an element `e` will verify `e = DES-Enc(k1, m)` for some key `k1` and `e = DES-Dec(k2, c)` for some key `k2`, meaning that `c = Double-DES(m)` for the couple of keys `(k1, k2)`.

Thus the adversary has broken Double-DES in only `O(|K|)` instead of `O(|K²|)` which is the key space of Double DES.

## Implementation

We implement this attack in Python, using the oracle provided to get one instance of a known encryption:

```python
FLAG = binascii.unhexlify("f43b78da788332852d43032ed02eba7421f879b6b7fdddf33ac4bd5c6db1d01da98bdfe10a838374")
MSG = pad(binascii.unhexlify("00").decode())
CTXT = binascii.unhexlify("627fa67e59022fd9")

def double_decrypt(k1, k2):
    cipher2 = DES.new(k2, DES.MODE_ECB)
    cipher1 = DES.new(k1, DES.MODE_ECB)
    middle = cipher2.decrypt(FLAG)
    ptxt = cipher1.decrypt(middle)
    return ptxt

all_ctxt = {}
all_ptxt = {}

for i in itertools.product(string.digits, repeat=6):
    k = pad("".join(i))
    cipher = DES.new(k, DES.MODE_ECB)
    ctxt = cipher.encrypt(MSG)
    if ctxt in all_ptxt:
        print("Found it!")
        print(double_decrypt(k, all_ptxt[ctxt]))
        break
    all_ctxt[ctxt] = k
    ptxt = cipher.decrypt(CTXT)
    if ptxt in all_ctxt:
        print("Found it!")
        print(double_decrypt(all_ctxt[ptxt], k))
        break
    all_ptxt[ptxt] = k
```

Flag: `e21cf83f64e53a743e685e55852feaf2`