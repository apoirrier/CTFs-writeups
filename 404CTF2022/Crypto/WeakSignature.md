# Weak Signature

> Un nouveau système a été mis en place pour exécuter du code de façon sécurisée sur l'infrastructure. Il suffit d'envoyer une archive signée et encodée en base 64 pour exécuter le code Python qu'elle contient !
>
> Vous trouverez la documentation de ce système et un exemple en pièces jointes. Tentez de voir si vous ne pourriez pas l'exploiter afin de lire le précieux fichier flag.txt

On nous donne la documentation suivante:

```md
# xX_SignedArchive_Xx

## File format

The signed archive file format is made of a header section followed by a data section. Here is how they are made :

**Header:**
- Magic number (5 bytes) : `01 5A 53 69 67`
- \x02 : `02`
- Signature of the data (36 bytes, 0-padded, big endian)
- \x03 : `03`
- Size of data section (4 bytes, 0-padded, big endian)
- \x04 : `04`

And then put the data section.

## Signature algorithm

- Compute the checksum of the data section
- Encrypt the checksum using the private key

## Verification algorithm

- Compute the checksum of the data section
- Decrypt the signature using the public key
- Compare the computed checksum with the decrypted signature
```

Ainsi que le code Python correspondant, et un fichier signé.

## Description

Comme décrit dans la notice d'utilisation, la signature ne dépend que de la somme de contrôle calculée à partir du fichier et non du fichier lui-même.

Ainsi, on peut chercher une collision entre le fichier fourni déjà signé, et un fichier Python qu'on souhaite exécuter.
Ils auront alors la même signature.

La fonction pour calculer la somme de contrôle est la suivante:

```python
def checksum(data: bytes) -> int:
    # Sum the integer value of each byte and multiply the result by the length
    chksum = sum(data) * len(data)

    return chksum
```

Un moyen de trouver une collision est donc d'avoir un fichier de même taille dont la somme est identique.

## Solution

First, we extract from the given signed file the Python script and its signature:

```python
from sign import checksum

with open("script.py.zsig", "rb") as f:
    magic = f.read(5)
    if magic != b"\x01ZSig":
        print("Error")
    
    f.read(1)
    signature_bytes = f.read(300)
    signature = int.from_bytes(signature_bytes, "big")

    f.read(1)
    size = int.from_bytes(f.read(4), "big")

    f.read(1)
    data = f.read()

    if len(data) != size:
        print("Error")

target = checksum(data)
```

We get the target checksum: it can be factorized as `2*7*61*1447`.

My goal is to find a script of size `2*61` where the sum of its bytes is `7*1447`.

To do so, I create a Python script printing the flag, then I add a comment and I will fill this comment with bytes so the length and sum will produce the correct checksum.

```python
myscript = """
print(open("flag.txt").read()) # """.encode()

target_len = 2*61
target_sum = 7*1447
assert(target_len * target_sum == target)

for i in range(target_len-len(myscript)):
    filler = (target_sum - sum(myscript)) // (target_len-len(myscript))
    myscript += chr(filler).encode()

assert(checksum(myscript) == target)
```

Once this is done, we can send the script:

```python
from base64 import b64encode
from pwn import *

size_bytes = len(myscript).to_bytes(4, "big")
out_bytes = b"\x01ZSig\x02" + signature_bytes + b"\x03" + size_bytes + b"\x04" + myscript
out64 = b64encode(out_bytes)

sh = remote("challenge.404ctf.fr", 32441)
sh.recvline()
sh.sendline(out64)
sh.interactive()
```

Flag: `404CTF{Th1s_Ch3cksum_W4s_Tr4sh}`