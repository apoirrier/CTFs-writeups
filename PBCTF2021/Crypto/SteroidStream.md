# Steroid Stream

> I found a weird stream cipher scheme. Can you break this?

The Python code:

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
    assert ln > 50
    
    # Generate some fake values based on the given key...
    fake = [0] * ln
    for i in range(ln - ln // 3):
        arr = list(range(i + 1, ln))
        random.shuffle(arr)
        for j in arr[:ln // 3]:
            fake[i] ^= key[j]

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

This challenge is similar to [Alkaloid Stream](AlkaloidStream.md) except that the `fake` values are computed differently.

To summarize, given the flag having `ln` bits, the challenge has created `ln` linearly independent keys.

Then for each `i` from 0 to `ln - ln//3`, `fake[i]` is created as the XOR of `ln//3` random different keys with index between `i+1` and `ln-1`.
Also public data is shuffled before publishing.

Thus the solution from the previous challenge does not work.

## Solution

We still want the same goal: to distinguish for each `i` the key from the fake.

First we know the last `ln//3` keys will have `fake[i] = 0`. So we have already found `ln//3` keys.

Then we recall that fake values are linear combinations of  keys that happen next.

So for instance, `fake[ln-ln//3-1]` will be the XOR of all `ln//3` keys that we have just found.

`fake[ln-ln//3-2]` will be a combination of `ln//3` keys amongst the `ln//3 + 1` we have found.

And we can continue to iterate like this.

As keys are all linearly independent, we have a differentiation criterium between keys and fakes: fakes will be linear combinations of other keys, but keys cannot be.

However we won't be able to find them all in one go, as we don't know all the keys. But at each step we will learn at least one new key, and so we can iterate until we have found all the keys.

To do this, I have copied the following function from [Stackoverflow](https://stackoverflow.com/questions/56856378/fast-computation-of-matrix-rank-over-gf2), which given a matrix of boolean gives me its rank.

```python
def gf2_rank(rows):
    """
    Find rank of a matrix over GF2.

    The rows of the matrix are given as nonnegative integers, thought
    of as bit-strings.

    This function modifies the input list. Use gf2_rank(rows.copy())
    instead of gf2_rank(rows) to avoid modifying rows.
    """
    rank = 0
    while rows:
        pivot_row = rows.pop()
        if pivot_row:
            rank += 1
            lsb = pivot_row & -pivot_row
            for index, row in enumerate(rows):
                if row & lsb:
                    rows[index] = row ^ pivot_row
    return rank
```

In my usage, I give matrices of size `ln * (k+1)` with `k` the total number of known keys, and the last row being the tested value `v`. If the rank is `k+1`, it means `v` is not a linear combination of the known keys, but if it is `k` then I have a linear combination meaning `v` is a fake value.

Thus I can define my function to determine if `test_value` is a linear combination of the keys:

```python
def is_linear_combination(keys, test_value):
    rows = keys.copy()
    rows.append(test_value)
    n = len(rows)
    return gf2_rank(rows) < n
```

And finally the complete exploit, which reads data from the input file, extract the `ln//3` first keys and then performs the fake values search.
At the end, I recover the keystream with the function given in the original file and decrypt the flag.

```python
## Reading input
with open("output_steroid.txt", "r") as f:
    c = bytes.fromhex(f.readline())
    c = bytes_to_bits(c)
    public = eval(f.read())

## Recovering last ln//3 keys
ln = len(public)
keys = []
remaining = []
for v in public:
    if 0 in v:
        keys.append(v[0] + v[1])
    else:
        remaining.append(v)

## Fake search
while len(remaining) > 0:
    remaining2 = []
    for v in remaining:
        if is_linear_combination(keys, v[0]):
            keys.append(v[1])
        elif is_linear_combination(keys, v[1]):
            keys.append(v[0])
        else:
            remaining2.append(v)
    remaining = remaining2
    print(len(remaining))

## End
keystream = recover_keystream(keys, public)

flag = bits_to_bytes(xor(c, keystream))
print(flag)
```

Flag: `pbctf{I_hope_you_enjoyed_this_challenge_now_how_about_playing_Metroid_Dread?}`