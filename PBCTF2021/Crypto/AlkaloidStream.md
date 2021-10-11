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

The Python file encrypts the flag with a stream cipher.
Let's denote `ln` the number of bits in the flag.

The file creates a keystream of `ln` bits, and the encryption of the flag is `xor(flag, keystream)`.
While creating the keystream, it also creates some public data that we can use to recover the keystream.

To get the flag, we thus need to understand how the keystream is created, then how we can recover it from the public data.

## Understanding the keystream generation

The keystream generation has several steps.

First a key composed of `ln` linearly independent integers is created, where `ln` is the size of the flag.
We denote each integer of the key `key[i]`.

Then given the key, a set of `ln` fake keys are created: for all `i`, `fake[i]` is the XOR of keys `key[j]` for `i+1 <= j < min(ln, i + ln//3)`.

Then the keystream of `ln` bits is randomly chosen.
The public data is formed as follows: if the `i`-th bit of the keystream is 1, then the `i`-th public information `public[i]` is `[fake[i], key[i]]` and `[key[i], fake[i]]` otherwise.

Finally, a permutation `pi` is randomly chosen, and the actual keystream used to encrypt the flag is `pi(keystream)` and we are given `pi(public)` as public information.


## Retrieving the keystream

What we observe is that for the last key element, there are no further key material. Therefore `fake[ln-1]` will necessarily be 0.
This is the only one value that can be 0.
Indeed, keys are generated as linearly independent, so no key can be null and no linear combination of keys can be null.

If we consider element `fake[ln-2]`, then it necessarily is equal to `key[ln-1]` which we have just found with the previous step.

We can iterate this method to retrieve all elements of the key, and thus find the keystream.

Formally, given keys `key[i+1], ..., key[ln-1]`, we can compute `fake[i]` as in the `fake` generation as we know the following keys.
We then search the fake value in the public data, and thanks to it we learn the value of `key[i]` as well as the keystream bit corresponding to this entry.

## Full solution

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