# Forgery

> Felicity and Cisco would like to hire you as an intern for a new security company that they are forming.
> They have given you a black box signature verification system to test out and see if you can forge a signature.
> Forge it and you will get a passphrase to be hired!
> 
> nc crypto.chal.csaw.io 5006

## Description

We are given the following Python file:

```python
from Crypto.Util.number import getPrime
from random import randint
from math import gcd

with open("flag.txt",'r') as f:
	flag = f.read()

p = getPrime(1024)
g = 3
MASK = 2**1024 - 1

def gen_keys():
	x = randint(1, p-2)
	y = pow(g, x, p)
	return (x, y)

def sign(answer: str, x: int):
	while True:
		m = int(asnwer, 16) & MASK
		k = randint(2, p-2)
		if gcd(k, p - 1) != 1:
			continue 
		r = pow(g, k, p)
		s = (m - x*r) * pow(k,-1,p-1) % (p - 1)
		if s == 0:
			continue
		return (r,s)

def verify(answer: str, r: int, s: int, y: int):
	m = int(answer, 16) & MASK
	if any([x <= 0 or x >= p-1 for x in [m,r,s]]):
		return False
	return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p

def main():
	x, y = gen_keys()
	print(f"Server's public key (p,g,y): {p} {g} {y}")
	print("Who do you think is the tech wizard: Felicity or Cisco or both? Please answer it with your signnature (r,s)")
	print('Answer: ')
	answer = input()
	print('r: ')
	r = int(input())
	print('s: ')
	s = int(input())
	answer_bytes = bytes.fromhex(answer)

	if b'Felicity' not in answer_bytes and b'Cisco' not in answer_bytes and b'both' not in answer_bytes:
		print("Error: the answer is not valid!")
	elif verify(answer, r, s, y):
		if b'Felicity' in answer_bytes:
			print("I see you are a fan of Arrow!")
		elif b'Cisco' in answer_bytes:
			print("I see you are a fan of Flash!")
		else:
			print("Brown noser!")
		print(flag)
	else:
		print("Error: message does not match given signature")

if __name__ == "__main__":
	main()
```

By reading it, we see that to get the flag we need to forge a signature for a string containing `Cisco`, `Felicity` or `both`.

Let's have a closer look at the signature system.
The system generates a 1024-bit prime `p`, selects a generator `g = 3` and generates a private key `x`.
The public key is `y = g^x`.

For signing a message `m`, the message is first masked and only the 1024 least significant bits are kept.
The signature is then computed as follows, by choosing a random value `k`:
```
r = g^k [p]
s = (m-xr) / k [p-1]
```

and verification is performed by checking if `g^m == y^r * r^s [p]`.

## Solution

This cryptosystem reminds us of the ElGamal signature scheme, except that instead of hashing the message it is only masked.
With a quick Google search for vulnerabilities on the ElGamal signature scheme without hash, we find a [thesis by Chan](https://core.ac.uk/download/pdf/48535618.pdf).
Section 3.2 shows how the ElGamal scheme without hash is not secure as we can derive forgeries from already formed signatures, and even create a forgery out of nothing by doing as follows:

Select integers `B, C` and compute:
```
r' = g^B * y^C [p]
s' = -r'C [p-1]
m' = -r'B/C [p-1]
```

What we can thus do is to forge such a message, prepend `Cisco` before it as it will be removed by the masking procedure, and send this to the server.
In the following code I choose `B=C=1`.

```python
from pwn import *
from Crypto.Util.number import *

sh = remote("crypto.chal.csaw.io", 5006)
sh.recvuntil("(p,g,y): ")
data = sh.recvline().decode()
data = [int(x) for x in data.split(" ")]
p,g,y = data[0],data[1],data[2]

r = g*y % p
s = (-r) % (p-1)
m = (-r) % (p-1)

signed_message = b"Cisco".hex() + long_to_bytes(m).hex().rjust(1024//4, "0")
sh.recvuntil("Answer:")
sh.sendline(signed_message)
sh.recvuntil("r:")
sh.sendline(str(r))
sh.recvuntil("s:")
sh.sendline(str(s))
sh.interactive()
```

Flag: `flag{7h3_4rr0wv3r53_15_4w350M3!}`
