# Difficult Decryption

> We intercepted communication between two VERY important people, named Alice and Bob. Can you figure out what this is supposed to mean?
> 
> Alice: "Bob, I need to tell you something."
> 
> Bob: "What?"
> 
> Alice: "It's top-secret, so let's use a secure encryption method."
> 
> Bob: "Is that really necessary? Like, who would listen?"
> 
> Alice: "Doesn't matter. This is really serious."
> 
> Bob: "Uh, okay then."
> 
> Alice: 
>
> Modulus: 491988559103692092263984889813697016406
>
> Base: 5
> 
> Base ^ A % Modulus:
>
> 232042342203461569340683568996607232345
>
> -----
> Bob: 
> Got it.
> 
> Here's my Base ^ B % Modulus:
>
> 76405255723702450233149901853450417505
>
> -----
> Alice: 
> Thanks. 
> 
> Here's the encoded message: 
> 12259991521844666821961395299843462461536060465691388049371797540470
> 
> I encoded it using this Python command: "message ^ (pow(your_key, A, modulus))". Your_key is Base ^ B % Modulus.
>
> After you decode the message, it will be a decimal number. Convert it to hex. You know what to do after that.
>
> -----
> Bob: Okay.
>
> Alice: Also, do NOT tell anyone what I just told you. I'll give you more information later.

## Description

We get an exchange between Alice and Bob. We can see the encoded message using a [one time pad](https://en.wikipedia.org/wiki/One-time_pad), the shared key being obtained using a [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange). 

As a remainder, the exchange works as follow:

- A common modulus `p` and a generator `g` are chosen. Here `p` is the modulus and `g` the base.
- Alice and Bob choose private keys `A` and `B`.
- They send to each other their public keys `pA = g^A [p]` and `pB = g^B [p]`
- They deduce the same shared key `K = pA ^ B = pB ^ A = g^(AB) [p]`.

Then this shared key is xored with the message to get the ciphertext.

## Solution

We will be using the [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) to solve the discrete logarithm problem. [This paper](http://anh.cs.luc.edu/331/notes/PohligHellmanp_k2p.pdf) explains it very well. The steps are as follow:
- first compute `phi(p)`, decompose it in prime factors.
- solve the DLP for every factor: this gives an easier subproblem
- combine al results using the Chinese Remainder Theorem.

Disclaimer: due to the very small values of factors, code shown here is not optimal.

### Helper functions

First we define some number theory helper functions.

#### Extended Euclid's Algorithm and Modular Inversion

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
```

([Source](https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python))

#### Very naïve factorization and phi computation

```python
def compute_phi(N):
    N_ = N
    phi = 1
    x = 2
    while N_ != 1:
        if N_ % x == 0:
            N_ //= x
            phi *= (x-1)
            while N_ % x == 0:
                N_ //= x
                phi *= x
        x += 1
    return phi

def factorize(N):
    N_ = N
    factors = []
    exponents = []
    x = 2
    while N_ != 1:
        if N_ % x == 0:
            N_ //= x
            factors.append(x)
            exponents.append(1)
            while N_ % x == 0:
                N_ //= x
                exponents[-1] += 1
        x += 1
    return factors, exponents
```

#### Gauss Algorithm for the CRT

```python
def ChineseRemainderGauss(n, N, a):
    result = 0
    for i in range(len(n)):
        ai = a[i]
        ni = n[i]
        bi = N // ni
        result += ai * bi * modinv(bi, ni)
    return result % N
```

([Source](https://medium.com/@astartekraus/the-chinese-remainder-theorem-ea110f48248c))

### Implementation of Pohlig–Hellman Algorithm

Then comes the real interesting part: the implementation of Pohlig–Hellman Algorithm.

First I define a naïve brute force for solving the DLP:

```python
def bruteforce_DLP(A, B, p, q):
    for i in range(q):
        if B == pow(A,i,p):
            return i
```

This function bruteforces the solution of the DLP `A^x = B [p]`, knowing the order of `A` is at most `q`.

Using this function, I can compute a DLP solution modulo `q^m` where `q` is prime. The following function finds `x` modulo `q^m` such that `alpha^x = beta [p]`. 

To do this, I express `x = a_0 + a_1 q + ... + a_{b-1} q^(b-1) [q^m]`, and I compute coefficients `a_i` one by one. Look at the paper cited above for more precise explanations.

```python
def easy_DLP(q, m, alpha, beta, p):
    A = pow(alpha, order//q, p)
    alpha1 = modinv(alpha,p)

    q_pow = 1
    x = 0
    for i in range(m):
        B = pow(beta, order // (q_pow*q), p)
        ai = bruteforce_DLP(A, B, p, q)
        x += (ai*q_pow)
        beta *= pow(alpha1, ai*q_pow, N)
        beta = beta % N
        q_pow *= q
    return x
```

Finally I can produce the Pohlig–Hellman Algorithm: it finds `x` such that `alpha^x = beta [p]` where `order` is the order of `alpha` in (Z/pZ)* and `beta` belongs in the subgroup generated by `alpha`.

```python
def pohlig_hellman(alpha, beta, p, order):
    remainders = []
    modulo = []
    factors, exponents = factorize(order)
    for q,m in zip(factors,exponents):
        remainders.append(easy_DLP(q, m, alpha, beta, p))
        modulo.append(q**m)

    return ChineseRemainderGauss(modulo, order, remainders)
```

### Finding the flag

With all our number theory algorithms, we can find the flag.

```python
# Define constants
N = 491988559103692092263984889813697016406
g = 5
yA = 232042342203461569340683568996607232345
yB = 76405255723702450233149901853450417505

ctxt = 12259991521844666821961395299843462461536060465691388049371797540470

# Find the subgroup generated by g
phi = compute_phi(N)
factors_phi, _ = factorize(phi)

order = phi
for p in factors_phi:
    while pow(g, order // p, N) == 1:
        order //= p
print("Order:", order)
# Order: 39329404631756038800

# Solve the DLP
xA = pohlig_hellman(g, yA, N, order)
print("Alice's secret key:", xA)
# Alice's secret key: 25222735067058727456

# Compute the shared key and decrypt the OTP
key = pow(yB, xA, N)
print(bytes.fromhex(hex(ctxt ^ key)[2:]))
```

Flag: `tjctf{Ali3ns_1iv3_am0ng_us!}`