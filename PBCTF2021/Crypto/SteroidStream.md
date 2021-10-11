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

To summarize, given the flag having `ln` bits, the challenge creates a keystream as follows:
- generate `ln` independent integers of `ln` bits denoted `key[i]`.
- for `i <= ln // 3`, compute `fake[i]` as the XOR of `ln//3` different keys randomly chosen in the set `[i+1, ln//3-1]`.
- generate a random `keystream` of size `ln` and define `public[i] = (fake[i], key[i]) if keystream[i] else (key[i], fake[i])`.
- choose a permutation `pi` and output the keystream `pi(keystream)` and public data `pi(public)`.


## Solution

We still want the same goal: to distinguish for each `i` the key from the fake.
Once we know the set of keys we can use the provided function `recover_keystream` to recover the keystream and decrypt the flag.

First we know the last `ln//3` keys will have `fake[i] = 0`. So we have already found `ln//3` keys.

We can then get a some sort of recurrence relation.

Indeed, we recall that fake values are linear combinations of keys, while keys cannot be as they are all linearly independent.
Therefore we have a way to differentiate them.

Formally, let's assume we know keys `key[i+1], ..., key[ln-1]`.

Then for every possible value `v` in public couples, we can detect if `v` is a linear combination of the aforementioned keys.
If it is a linear combination, then it is necessarily a fake value.

Moreover, we know that `fake[i]` is a linear combination of those values.
Thus there is at least one value that will match, and thus we have learned at least one new key to reiterate.

### Detect if a value is a linear combination of others

Let `known_keys` be a set of keys known and let `k` be its cardinal.

To detect if a value `v` is a linear combination of elements of `known_keys`, I put them all in a GF(2) matrix where the rows are the keys and last row is the element.

If I don't put `v` in the matrix, I have a matrix of size `k * ln` with `k` independent rows.
Therefore the matrix rank is `k`.

If I now add the value as the `(k+1)`-th row, if it is a linear combination of the keys, the rank will still be `k`, otherwise it will be `k+1`.

To compute matrix ranks, I have copied the following function from [Stackoverflow](https://stackoverflow.com/questions/56856378/fast-computation-of-matrix-rank-over-gf2), which given a matrix of boolean gives me its rank.

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

Then I have defined my function to determine if `test_value` is a linear combination of the keys:

```python
def is_linear_combination(keys, test_value):
    rows = keys.copy()
    rows.append(test_value)
    n = len(rows)
    return gf2_rank(rows) < n
```

### Full exploit

The complete exploit reads data from the input file, extracts the `ln//3` first keys and then performs the fake values search.
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