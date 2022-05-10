# Gaston La Paffe

> Gaston travaille dans une administration. Il passe son temps à traiter des courriers divers. Il trouve que son emploi n'est pas rémunéré à sa juste valeur : cela fait plus de 10 ans qu'il n'a pas eu de prime alors qu'il ne fait que 3 siestes par jour ! Comble de l'injustice, parmi tous les courriers qu'il a traité les 10 ans passés, il a vu passer plus de 500 notifications de primes pour ses collègues.
>
> Ces notifications sont malheureusement toutes signées avec une méthode innovante inventée par la direction. Seule la direction a la clé privée permettant de signer.
>
> Gaston a rédigé son courrier de prime idéal. S'il y avait un moyen d'y ajouter la signature de la direction, il glisserait sa notification avec les autres. Comme la direction n'a qu'une parole, ils lui accorderaient cette prime !
>
> On dirait bien qu'il y a une fuite dans la méthode signature. Gaston compte sur vous pour l'aider à retrouver la clé de signature utilisée par sa direction.

We are given the following code to sign and verify signatures. We are also given 500 messages with their signature and an intermediate computation performed in the signature.

```python
import os
import json
import hashlib
import string
import numpy as np
from Crypto.Random.random import randint, choice
from Crypto.Hash import SHA512, SHA256
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

Q = 8383489
B = 16384
N = 512

class Server:
    def __init__(self, Q, B, N):
        self.Q = Q
        self.B = B
        self.N = N
        self.a = [randint(0, Q - 1) for _ in range(self.N)]
        self.__s1 = [randint(-1, 1) % Q for _ in range(self.N)]
        self.__s2 = [randint(-1, 1) % Q for _ in range(self.N)]
        self.t = self.poly_mul_add(self.a, self.__s1, self.__s2)

    def sk(self):
        return self.__s1, self.__s2

    def pk(self):
        return self.a, self.t

    def H(self, v1, m):
        h = bytes_to_long(SHA512.new(str(v1).encode() + m).digest())
        h = list(map(int, list(f"{h:0512b}")))
        return h

    def poly_add(self, p1, p2):
        return [ (p1[i] + p2[i]) % self.Q for i in range(self.N) ]

    def poly_sub(self, p1, p2):
        return [ (p1[i] - p2[i]) % self.Q for i in range(self.N) ]

    def poly_mul_add(self, p1, p2, p3):
        return self.poly_add(self.poly_mul(p1, p2), p3)

    def poly_mul(self, p1,p2):
        res = np.convolve(p1, p2)
        res = [0] * (2 * self.N - 1 - len(res)) + list(res)
        a = list(map(int, res[:self.N]))
        b = list(map(int, res[self.N:] + [0]))
        res = self.poly_sub(a, b)
        return res

    def reject(self, z):
        for v in z:
            if v > self.B and v < self.Q - self.B:
                return True
        return False

    def sign(self, m):
        while True:
            y1 = [ randint(-self.B, self.B) % self.Q for _ in range(self.N) ]
            y2 = [ randint(-self.B, self.B) % self.Q for _ in range(self.N) ]
            h = self.poly_mul_add(self.a, y1, y2)
            c = self.H(h, m)
            z1 = self.poly_mul_add(self.__s1, c, y1)
            z2 = self.poly_mul_add(self.__s2, c, y2)
            if self.reject(z1) or self.reject(z2):
                continue
            return y1, z1, z2, c

    def verify(self, z1, z2, c, m):
        if self.reject(z1) or self.reject(z2):
            return False
        temp1 = self.poly_mul_add(self.a, z1, z2)
        temp2 = self.poly_mul(self.t, c)
        h = self.poly_sub(temp1, temp2)
        c_prime = self.H(h, m)
        return c == c_prime

def get_random_string(length):
    return ''.join(choice(string.ascii_letters) for _ in range(length))

if __name__ == "__main__":

    server = Server(Q, B, N)
    a, t = server.pk()
    print(json.dumps({
        "a": a,
        "t": t,
    }))

    data = []
    for i in range(N):
        message = get_random_string(20)
        y1, z1, z2, c = server.sign(message.encode())
        assert server.verify(z1, z2, c, message.encode()), "Error: verification error."
        data.append({
            "message": message,
            "z1": z1,
            "z2": z2,
            "c": c,
            "y1": y1,
        })
    print(json.dumps(data))

    flag = open("flag.txt", "rb").read()
    s1, s2 = server.sk()
    key = SHA256.new(str(s1).encode() + str(s2).encode()).digest()
    iv = os.urandom(16)
    E = AES.new(key, AES.MODE_CBC, iv = iv)
    enc = E.encrypt(pad(flag, 16))
    print(json.dumps({
        "iv": iv.hex(),
        "enc": enc.hex()
    }))

```

## Analysis

The signature scheme is using polynomials in <img src="../images/gaston_zqzxn_dark.png#gh-dark-mode-only" height=15px><img src="../images/gaston_zqzxn_light.png#gh-light-mode-only" height=15px> (Q is a prime) represented as arrays.

Given a private key:

<img src="../images/gaston_s1s2_dark.png#gh-dark-mode-only" height=40px><img src="../images/gaston_s1s2_light.png#gh-light-mode-only" height=40px>

the public key is defined as:

<img src="../images/gaston_at_dark.png#gh-dark-mode-only" height=40px><img src="../images/gaston_at_light.png#gh-light-mode-only" height=40px>

The addition for polynomials is the standard addition, but the multiplication is a little bit different: the coefficient corresponding to degree `k` is the soustraction of the `k`-th usual coefficient for the multiplication with the `(k+N)`-th coefficient.

Signing a message `m` is performed as follows:
- two polynomials `y_1, y_2` are randomly sampled;
- `h = a*y_1 + y_2`;
- `c = SHA512(h || m)`;
- `(z1, z2) = (s1*c+y1, s2*c+y2)`
- the signature is `(y1, z1, z2, c)`.

The scheme is sound, as given a message `m`, a signature and the public key, we can verify the signature as follows:
- `(temp1, temp2) = (a*z1+z2, t*c)`;
- `h' = temp1 - temp2`;
- `c' = SHA512(h' || m)`
- The signature is correct if `c == c'`.

In the case where the signature has been generated with `sign`, then:

```
h' = temp1 - temp2
h' = a*z1 + z2 - t*c
h' = a*(s1*c + y1) + s2*c + y2 - (a*s1 + s2)*c
h' = a*y1  + y2
```
So `h' == h` and thus `c == c'`.

The goal is to find the secret key of the signature scheme given N signatures.

What we can observe is that `y1` is not really necessary in the signature, as we can verify without it.
Its value will in fact be crucial to help us find the secret key, and we will need only 1 signature.

Indeed, for any signature, the following relation is true:

```
z1 = s1*c+y1
```

In this relation, `z1, c, y1` are known, which will give us the value of `s1`. As `s2 = t - a*s1`, it is easy to recover `s2` and the full secret key.

## Solution

The difficult part is to retrieve `s1` from the relation `z1 = s1*c+y1`.
Let's expand the computation from `s1*c`:

<img src="../images/gaston_s1c_dark.png#gh-dark-mode-only" height=80px><img src="../images/gaston_s1c_light.png#gh-light-mode-only" height=80px>

We get the second line by performing a change of variable `k <- k-N` and by removing zero terms from the inner sum.

This is a system of `N` equations (one for every `k`) with N unknown variables (the `s_i`).

So we can just inverse the matrix to solve the linear system and get the solution.

```python
import json
from Crypto.Util.Padding import unpad

from gaston import *

serv = Server(Q, B, N)

with open('output.txt', 'r') as f:
    s = f.read().split("\n")
    pk = json.loads(s[0])
    signatures = json.loads(s[1])
    ctxt = json.loads(s[2])

a = pk["a"]
t = pk["t"]
z1 = signatures[0]["z1"]
z2 = signatures[0]["z2"]
y1 = signatures[0]["y1"]
c = signatures[0]["c"]

z1_y1 = [x if x < Q//2 else x-Q for x in serv.poly_sub(z1, y1)]

A = [[c[k-i] for i in range(k+1)] + [-c[k+N-i] for i in range(k+1,N)] for k in range(N)]
A = np.matrix(A)
s1 = A.getI().dot(z1_y1)
s1 = [int(np.round(s1[0,i], 0)) % Q for i in range(N)]

s2 = serv.poly_sub(t, serv.poly_mul(a, s1))

key = SHA256.new(str(s1).encode() + str(s2).encode()).digest()
E = AES.new(key, AES.MODE_CBC, iv = bytes.fromhex(ctxt["iv"]))
ptxt = unpad(E.decrypt(bytes.fromhex(ctxt["enc"])), 16)
print(ptxt)
```

Flag: `FCSC{c3b929519b28954612bf81af628dd93b6adef1e79539887729e1a2a27569eeb0}`