# One True Problem

Cryptography

## Description

> Two of my friends were arguing about which CTF category is the best, but they encrypted it because they didn't want anyone to see. Lucky for us, they reused the same key; can you recover it?
> 
> Here are the ciphertexts:
> 
> 213c234c2322282057730b32492e720b35732b2124553d354c22352224237f1826283d7b0651
> 
> 3b3b463829225b3632630b542623767f39674431343b353435412223243b7f162028397a103e

## Solution

From the name and the size of the ciphertexts I deduce this is a two time pad (One Time Pad with key reused). 

Therefore the plaintexts P1 and P2 are linked with the equation:

![](https://latex.codecogs.com/gif.latex?P_1%20%5Coplus%20P_2%20%3D%20C_1%20%5Coplus%20C_2)

(with C1, C2 being the ciphertexts).

As we know the key probably begins by `utflag`, we can XOR this string with C1 and C2. This works, and yields the beginning of both plaintexts. 

```
P1: THE B wS+iR+Sul_8[&q
P2: NO THE{C+tV_Gd6Z0
```

Then by guessing the next characters in one plaintext, one is able to decrypt the other and guess the whole plaintexts. Here for example next character in P2 is probably a space. 

A small Python script to help decoding:
```python
C1 = "213c234c2322282057730b32492e720b35732b2124553d354c22352224237f1826283d7b0651"
C2 = "3b3b463829225b3632630b542623767f39674431343b353435412223243b7f162028397a103e"

C1_ = bytes.fromhex(C1)
C2_ = bytes.fromhex(C2)

P = [ord(c) for c in 'NO THE ']
print(P)
xor = [C1_[i] ^ C2_[i] for i in range(len(C1_))]
for i in range(len(P)):
    xor[i] ^= P[i]

print("".join([chr(i) for i in xor])[:len(P)])
```

Finally, I have been able to recover both plaintexts:
```
P1 = THE BEST CTF CATEGORY IS CRYPTOGRAPHY!
P2 = NO THE BEST ONE IS BINARY EXPLOITATION
```

To get the key, just XOR a plaintext and a ciphertext:
```python
xor = [C2_[i] for i in range(len(C1_))]
P2 = [ord(i) for i in 'NO THE BEST ONE IS BINARY EXPLOITATION']
for i in range(len(P2)):
    xor[i] ^= P2[i]

print("".join([chr(i) for i in xor]))
# Prints utflag{tw0_tim3_p4ds}utflag{tw0_tim3_p
```

Flag: utflag{tw0_tim3_p4ds}
