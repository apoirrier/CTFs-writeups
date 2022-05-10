# T-Rex

> Vous devez déchiffrer le flag :-)

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class TRex:
	def __init__(self, key):
		N = len(key)
		M = 2 ** (8 * N)
		self.key = key
		self.iv = int.from_bytes(key, "big")
		R = lambda x: ((2 * x + 1) * x)
		for _ in range(31337):
			self.iv = R(self.iv) % M
		self.iv = int.to_bytes(self.iv, N, "big")

	def encrypt(self, data):
		E = AES.new(self.key, AES.MODE_CBC, iv = self.iv)
		return self.iv + E.encrypt(pad(data, 16))

if __name__ == "__main__":
	E = TRex(os.urandom(16))
	flag = open("flag.txt", "rb").read().strip()
	c = E.encrypt(flag)
	print(c.hex())
```

## Description

The objective is to find the initial AES key, knowing the IV that is derived from the key.

We have the following relation:
```python
self.iv = int.from_bytes(key, "big")
R = lambda x: ((2 * x + 1) * x)
for _ in range(31337):
    self.iv = R(self.iv) % M
```

As the number 31337 seems arbitrary, we guess that we need to invert the function `R`.

I'm not sure if there is an arithmetic way to solve this.
I did it by recovering the bits from the antecedent one by one.

## Solution

Indeed, I remarked that the bit 0 of `R(x)` is the same as bit 0 of `x`, thus I can easily recover bit 0 of the key.

This is in fact a more general property: as bit `i` of `2x*x` only depends on bits `0` to `i-1` of `x`, we have the relation for all `i`:

<img src="../images/trex_dark.png#gh-dark-mode-only" height=40px><img src="../images/trex_light.png#gh-light-mode-only" height=40px>

Thus we can easily find `x_i` by induction.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("output.txt", "rb") as f:
    c = bytes.fromhex(f.read().decode())

IV = int.from_bytes(c[:16], "big")

def int_to_array(x):
    return [(x & (1 << i)) >> i for i in range(16*8)]

def array_to_int(x):
    s = 0
    for i in range(16*8):
        if x[i]:
            s += 1 << i
    return s

def find_antecedant(y):
    current_x = y&1
    for l in range(1, 128):
        mod = 1 << (l+1)
        s_mod = 2*current_x*current_x % mod
        y_mod = y % mod
        current_x = (y_mod - s_mod) % mod
    return current_x

key = IV
for _ in range(31337):
    key = find_antecedant(key)

cipher = AES.new(int.to_bytes(key, 16, "big"), AES.MODE_CBC, iv=c[:16])
ptxt = cipher.decrypt(c[16:])
print(unpad(ptxt, 16))
```

Flag: `FCSC{54a680c151c2bff32fd2fdc12b4f8558012dc71e429f075bab6bfc0322354bf4}`