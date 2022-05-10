# My Tailor is Rich

> Vos collègues experts en reverse engineering ont reconstitué un algorithme d'encodage de mots de passe d'un certain équipement. Ils se doutent qu'il est cryptographiquement faible mais ils font appel à vos services pour le démontrer.
>
> nc challenges.france-cybersecurity-challenge.fr 2100


```python
import string
import random

N = 8

def encode(pwd):
    def F(tmp):
        if tmp % 2:
            return (tmp % 26) + ord('A')
        else:
            r = tmp % 16
            if r < 10:
                return ord('0') + r
            else:
                return r - 10 + ord('A')

    a, res = 0, []
    for i in range(len(pwd)):
        P, c, S = pwd[:i], pwd[i], pwd[i+1:]
        S1, S2, T = sum(P), sum(S), sum(pwd)
        a = F((a + c) * i + T)
        res.append(a)

    return bytes(res)

def get_random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length)).encode()

pwd = get_random_string(8)
enc = encode(pwd)

print(f'Can you find {N} different passwords that encode to "{enc.decode()}"?')

P = []
S = [enc]
try:
    for _ in range(N):
        p = input(">>> ").encode()
        if not p.isascii():
            print("Please enter only ASCII strings.")
            exit(1)
        P.append(p)
        S.append(encode(p))

    if len(set(P)) == N and len(set(S)) == 1:
        print("Congrats!! Here is your flag:")
        print(open("flag.txt").read())
    else:
        print("Nope!")
except:
    pass

```

## Solution

Let `encoded` be the encoded password.
We have the following relations:

```python
T = sum(password)
encoded[0] = F(T)
encoded[i] = F((encoded[i-1]+password[i]) * i + T)
```

Given some `y`, `y` doesn't have a lot of antecedents by F (we can enumerate all possibilities).
We can thus do a wild bruteforce: First we fix T.
Then for every `i`, we check which character `password[i]` would verify the induction relation and we add it to the list of possible characters.

This gives us some candidate passwords, we can eliminate more by computing `password[0] = T - sum(password[1:])` and check if it is an ASCII character.

If that is the case, then it means we have found a valid password, so we can add it to the list.
We stop when we reach 8 possible passwords.

```python
import itertools
import string
from pwn import *

# Paste code of F and encode here

sh = remote("challenges.france-cybersecurity-challenge.fr", 2100)
code = sh.recvline().decode()
password = code.split('"')[1].encode()
print(password)
candidates = []

for T in range(128*8):
    if F(T) == password[0]:
        possibles = [[] for _ in range(8)]
        for character in range(1,8):
            for c in string.ascii_letters:
                c = ord(c)
                if F((password[character-1] + c)*character + T) == password[character]:
                    possibles[character].append(c)
        for c in itertools.product(*possibles[1:]):
            if sum(c) > T or not bytes([T-sum(c)]).isascii():
                continue
            z0 = T - sum(c)
            candidate = bytes([z0]) + bytes(c)
            if encode(candidate) == password:
                candidates.append(candidate)
            break
        if len(candidates) >= 8:
            break

print(candidates)

for x in candidates:
    sh.recvuntil(b">>> ")
    sh.sendline(x)
sh.interactive()
```

Running time of the brute force is less than a minute.

Flag: `FCSC{515dd8416571401f2f0bf039e9adeec0cb9c51f4430923baa9fcb3fa13e14091}`
