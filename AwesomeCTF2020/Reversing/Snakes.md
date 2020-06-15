# Snakes and Ladders

> The flag is fqtbjfub4uj_0_d00151a52523e510f3e50521814141c. The attached file may be useful.

```python
def xor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def encrypt(a):
    some_text = a[::2]

    randnum = 14
    text_length = len(some_text)
    endtext = ""
    for i in range(1, text_length + 1):
      weirdtext = some_text[i - 1]
      if weirdtext >= "a" and weirdtext <= "z":
          weirdtext = chr(ord(weirdtext) + randnum)
          if weirdtext > "z":
              weirdtext = chr(ord(weirdtext) - 26)
      endtext += weirdtext
    randtext = a[1::2]

    xored = xor("aaaaaaaaaaaaaaa", randtext)
    hex_xored = xored.encode("utf-8").hex()

    return endtext + hex_xored

def decrypt(msg):
    pass

def main():
    opt = input("Would you like to [E]ncrypt or [D]ecrypt? ")
    if opt[:1].lower() == "e":
        msg = input("Enter message to encrypt: ")
        print(f"Encrypted message: {encrypt(msg)}")
    elif opt[:1].lower() == "d":
        msg = input("Enter message to decrypt: ")
        print(f"Decrypted message: {decrypt(msg)}")

if __name__ == "__main__":
    main()
```

## Description

This is a reversing challenge, where we get the encryption of a flag and the program to encrypt data. The objective is to write the decryption function.

## Solution

Let's analyse the encryption function.

```python
def encrypt(a):
    some_text = a[::2]

    randnum = 14
    text_length = len(some_text)
    endtext = ""
    for i in range(1, text_length + 1):
      weirdtext = some_text[i - 1]
      if weirdtext >= "a" and weirdtext <= "z":
          weirdtext = chr(ord(weirdtext) + randnum)
          if weirdtext > "z":
              weirdtext = chr(ord(weirdtext) - 26)
      endtext += weirdtext
    randtext = a[1::2]

    xored = xor("aaaaaaaaaaaaaaa", randtext)
    hex_xored = xored.encode("utf-8").hex()
    return endtext + hex_xored
```

The ciphertext is composed of two parts: `endtext` and `hex_xored`. 

`hex_xored` is the hex encoded string of `aaaaaaaaaaaaaaa xor randtext`, with `randtext` being all odd characters of the input buffer.

`endtext` is created using the for loop. `some_text` is initialised with all even characters of the input buffer, then each character in `some_text` corresponds to one character of `endtext`. If the character is a lowercase letter, then `14` is added to it, and if if goes beyond `z`, `26` is substracted: this is a Caesar cipher with key `14`.

Therefore the first third of ciphertext is `endtext`, the remaining is `hex_xored`, and decrypting is easy: for the first part, apply the invert Caesar cipher, for the second part, xor again with `aaaaaaaaaaaaaaa`.

Here is the decryption procedure:

```python
def decrypt(msg):
    end_text = msg[:len(msg)//3]
    hex_xored = msg[len(msg)//3+1:]
    
    xored = bytes.fromhex("0" + hex_xored).decode()
    randtext = xor("aaaaaaaaaaaaaaa", xored)

    some_text = ""
    for c in end_text:
        if c < 'a' or c > 'z':
            some_text += c
        else:
            c2 = ord(c) - 14
            if c2 < ord('a'):
                c2 += 26
            some_text += chr(c2)

    for c1,c2 in zip(some_text, randtext):
        print(c1, end="")
        print(c2, end="")
```

Flag: `ractf{n3v3r_g0nn4_g1v3_y0u_up}`