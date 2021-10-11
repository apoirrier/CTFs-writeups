# Alkaloid Stream

> I found a weird stream cipher scheme. Can you break this?

Attached are a Python file and its output.

```python
#!/usr/bin/env python3

import random
from flag import flag

def keygen(ln):
    # Generate a linearly independent key
    arr = [ 1 << i for i in range(ln) ]

    for i in range(ln):
        for j in range(i):
            if random.getrandbits(1):
                arr[j] ^= arr[i]
    for i in range(ln):
        for j in range(i):
            if random.getrandbits(1):
                arr[ln - 1 - j] ^= arr[ln - 1 - i]

    return arr

def gen_keystream(key):
    ln = len(key)
    
    # Generate some fake values based on the given key...
    fake = [0] * ln
    for i in range(ln):
        for j in range(ln // 3):
            if i + j + 1 >= ln:
                break
            fake[i] ^= key[i + j + 1]

    # Generate the keystream
    res = []
    for i in range(ln):
        t = random.getrandbits(1)
        if t:
            res.append((t, [fake[i], key[i]]))
        else:
            res.append((t, [key[i], fake[i]]))

    # Shuffle!
    random.shuffle(res)

    keystream = [v[0] for v in res]
    public = [v[1] for v in res]
    return keystream, public

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def recover_keystream(key, public):
    st = set(key)
    keystream = []
    for v0, v1 in public:
        if v0 in st:
            keystream.append(0)
        elif v1 in st:
            keystream.append(1)
        else:
            assert False, "Failed to recover the keystream"
    return keystream

def bytes_to_bits(inp):
    res = []
    for v in inp:
        res.extend(list(map(int, format(v, '08b'))))
    return res

def bits_to_bytes(inp):
    res = []
    for i in range(0, len(inp), 8):
        res.append(int(''.join(map(str, inp[i:i+8])), 2))
    return bytes(res)

flag = bytes_to_bits(flag)

key = keygen(len(flag))
keystream, public = gen_keystream(key)
assert keystream == recover_keystream(key, public)
enc = bits_to_bytes(xor(flag, keystream))

print(enc.hex())
print(public)
```

## Description

Let's read the Python file.
First a key composed of `ln` linearly independent integers is created, where `ln` is the size of the flag.

Then given the key, a set of fake key elements are created: for every key element at position `i`, the next `ln//3` key elements (if there are enough) are xored to create `fake[i]`.

Then the keystream is randomly chosen.
The public data is formed as follows: if the `i`-th bit of the keystream is 1, then the `i`-th public information is `[fake[i], key[i]]` and `[key[i], fake[i]]` otherwise.
However public information is shuffled so we don't have information on the key order.

As with stream ciphers, the ciphertext is the xor of the plaintext and the keystream.

What we observe is that for the last key element, there are no further key material. Therefore `fake[ln-1]` will necessarily be 0, and as key elements are linearly independent this is the only one.

If we consider element `fake[ln-2]`, then it necessarily is equal to `key[ln-1]` which we have just found with the previous step.

We can iterate this method to retrieve all elements of the key, and thus find the keystream. 

## Solution

I'm reusing the functions given in the file.

The outer for loop will find every key element and fill the `key` and `keystream` arrays.

The inner `j` loop performs the computation of `fake[i]` as during the keystream generation, as we know all keys to compute it.

Then the inner `k` loop searches which row in `public` has the fake value, and deduces from it the key value and keystream bit.

```python
with open("output.txt", "r") as f:
    c = bytes.fromhex(f.readline())
    c = bytes_to_bits(c)
    public = eval(f.read())

ln = len(public)
key = [0] * ln
keystream = [0] * ln
for i in range(ln-1,-1,-1):
    fake = 0
    for j in range(ln // 3):
        if i + j + 1 >= ln:
            break
        fake ^= key[i + j + 1]
    for k in range(ln):
        if fake in public[k]:
            if fake == public[k][0]:
                keystream[k] = 1
                key[i] = public[k][1]
            else:
                keystream[k] = 0
                key[i] = public[k][0]
            public[k] = [-1, -1]
            break

flag = bits_to_bytes(xor(keystream, c))
print(flag)
```

Finally the xor operation is performed and the flag is recovered.

Flag: `pbctf{super_duper_easy_brute_forcing_actually_this_one_was_made_by_mistake}`