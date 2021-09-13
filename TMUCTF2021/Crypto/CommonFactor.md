# Common Factor

> How much do you know about the RSA algorithm?

## Description

We are given a Python file

```python
from Crypto.Util.number import *
from functools import reduce


def encrypt(msg, n):
    enc = pow(bytes_to_long(msg), e, n)
    return enc


e = 65537

primes = [getPrime(2048) for i in range(5)]
n = reduce(lambda a, x: a * x, primes, 1)
print(n)

x1 = primes[1] ** 2
x2 = primes[2] ** 2
x3 = primes[1] * primes[2]
y1 = x1 * primes[2] + x2 * primes[1]
y2 = x2 * (primes[3] + 1) - 1
y3 = x3 * (primes[3] + 1) - 1
print(x2 + x3 + y1)
print(y2 + y3)

with open('flag', 'rb') as f:
    flag = f.read()
    print(encrypt(flag, n))
```

and its output as a text file (you can find it [here](data/output.txt) if interested).

The goal will be to decrypt the message.

## Solution

I give the modulus to factordb, and I get only 3 out of the five primes it is composed of.
Well I think my ciphertext and plaintext are smaller than `N' = p1*p2*p3`, so actually I don't care about the other 2 and can perform all computations in Z/N'Z.

```python
from Crypto.Util.number import *

def decrypt(p1, p2, p3, e, c):
    N = p1*p2*p3
    phi = (p1-1)*(p2-1)*(p3-1)
    d = inverse(e, phi)
    p = pow(c,d,N)
    return long_to_bytes(p)
```

Flag: `TMUCTF{Y35!!!__M4Y_N0t_4lW4y5_N33d_4ll_p21M3_f4c70R5}`