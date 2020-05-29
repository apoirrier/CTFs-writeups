# Unimportant

> It's probably at least a bit important? Like maybe not the least significant, but still unimportant...

Attached is an image and the following Python code:

```python
#!/usr/bin/env python3

from PIL import Image
import binascii

def encode(img, bits):
	pixels = img.load()
	i = 0
	for x in range(img.width):
		for y in range(img.height):
			pixel = pixels[x,y]
			pixel = (pixel[0], pixel[1]&~0b10|(bits[i]<<1), pixel[2], pixel[3])
			pixels[x,y] = pixel
			i += 1
			if i == len(bits):
				return

img = Image.open("source.png")

with open("flag.txt", "rb") as f:
	flag = f.read()
binstr = bin(int(binascii.hexlify(flag), 16))
bits = [int(x) for x in binstr[2:]]

encode(img, bits)

img.save("unimportant.png")
```

## Description

Well as the source is given, this challenge looks more like a reversing challenge than a forensics one. We get a source image and a flag, and the flag is encoded into the image. We just need to reverse it.

## Solution

Each bit of the flag is encoded in the pixel 1 of the image with the following formula:

```python
encoded[i] = pixel[i][1]&~0b10|(bits[i]<<1)
```

Meaning it is encoded in the second least significant bit. I'm just reusing their code to get the flag.

```python
from PIL import Image

def decode(img, size):
	pixels = img.load()
	bits = []
	i = 0
	for x in range(img.width):
		for y in range(img.height):
			pixel = pixels[x,y]
			bits.append((pixel[1]&0b10)>>1)
			i += 1
			if i == size:
				return bits

img = Image.open("unimportant.png")
# Bruteforce the offset
for offset in range(0, 4):
	bits = decode(img, 400+offset)
	bits_str = "".join(str(c) for c in bits)
	bits_int = int(bits_str, 2)
	bits_hex = hex(bits_int)
	if bits_hex[2:4] == "74": # This is a t
		print(bytes.fromhex(bits_hex[2:2*(len(bits_hex)//2)]))
```

Flag: `tjctf{n0t_th3_le4st_si9n1fic4nt}`

