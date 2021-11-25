# Crypto Be Crushed

> Vous participez à un CTF, ainsi que votre colocataire, Alice, avec laquelle vous partagez la même connexion internet et le Wifi.
> 
> Reconnaissons-le, vous êtes un peu paresseux : pourquoi résoudre un challenge si elle l’a déjà terminé ?
> 
> Cependant, comme expliqué dans les règles du CTF, les soumissions de flag sont chiffrées avec une clé propre à chaque utilisateur (voir le fichier CTF_Submission.md) et même si vous avez réussi à capturer la solution du dixième challenge, celui-ci est chiffré (en hexadécimal) :
>
> 61499b3f31cee611a72eaf3cbfcf7d1cebb228a44db94e7b0504c145fcf00e57d2e0b9e24c7259bbeebccd03c100a645f418f2f58cc073cc71f214eb64a3b20ddfb406f6ebbd6781119efe13116af3abfe52609961727213ea69b8f8f1e4298ed3a42bc9ae4b8f1785184153ee3e113a8c9d55ddec48c85c53d5aa4a4089e47c3026a0bdb4d5d2659e57c31a76cca407ea0a92430d8540b8ef677405e8c4b193
>
> Heureusement, Alice a décidé d’adapter le script de chiffrement fourni par l’organisateur du CTF et l’a transformé en un serveur de chiffrement.
> 
> Par chance, Alice a oublié de configurer correctement son pare-feu et vous êtes capable d’y accéder
> 
> > Attention, ce challenge redémarre toutes les heures, il se peut que vous soyez obligé de soumettre votre solution à nouveau si pour n'arrivez pas à la valider.

CTF_Submission.md
```md
# CTF Submission instructions

Welcome to the CTF, player!

This year, for security purposes, we decided to use specific procedure for you to use when submitting a flag.
Indeed, it must be submitted in a CBC-encrypted-JSON with a per-user key. We sent you the key at registration.
If you are not comfy with cryptography, no worries, you will find the code in the FAQ (`encrypt_challenge.py`, which uses the `PyCryptodome` library -- *don't roll your own crypto*).
You will just have to put your provided key in a `key.txt` file.

To be properly processed, the JSON file must have the following format :
- a `"sig"` value, with a random 32 bytes values encoded as a hex string which is provided to you for each challenge;
- a `"flag"` value containing the submitted flag;
- a `"user"` value, the user's login;
- and a `"cid"` value, which is the challenge id.

An example JSON is provided by the `ex_flag.json` file.

Happy hacking!
```

encrypt_challenge.py
```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto import Random
import secrets


def pkcs7_padding(m):
    # There is padding and there is PKCS#7 padding 🤮
    l = len(m)
    pad_len = 16 - (l % 16)
    pad_len_hex = pad_len.to_bytes(1, byteorder="little")
    padding = bytes([pad_len_hex[0] for i in range(0, pad_len)])

    return m+padding


# Prevent IV replays
iv_list = set()


def encrypt(iv, m):

    if iv in iv_list:
        print("ERROR: REPLAYED IV")
        return bytes([])

    iv_list.add(iv)

    m = pkcs7_padding(m)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(m)


def get_iv():
    return Random.new().read(AES.block_size)


KEY = open('key.txt', 'rb').read()

# stdin/stdout version
if __name__ == "__main__":
    while True:
        iv = get_iv()
        print("IV for encryption (hex):")
        print(iv.hex())
        print("Enter message (as a hex bytes string):")
        x = bytes.fromhex(input())
        # print("Message: " + str(x) + "\n")
        print("Ciphertext (hex): " + str(encrypt(iv, x).hex()) + "\n")
```

ex-flag.json
```json
{"sig":"80a7ccd5aa2f3b0f917267640c6ff37c50e7f3673a30d20c0e133fe8c20d5cd1","flag":"DG'hAck-{{b51613f7}}","user":"JohnDoe","cid": 4}
```

## Description of the vulnerability

We get the ciphertext encrypted with AES-CBC of a flag sent by Alice for the tenth challenge and need to find the flag.

To help us, we get access to an encryption oracle that gives us the IV that will be used for encryption, then encrypts our message.

Let's recall how AES encryption works.
Given a message `m`, pad it by adding between 1 and 16 bytes so it is a multiple of 16 bytes, and split it as blocks `pad(m) = m[1] | ... | m[n]`.

Then choose a random 16-bytes Initialisation Vector `c[0] = m[0]` and compute the ciphertext blocks for i > 0:

```
c[i] = AES(c[i-1] ^ m[i])
```

which is summarized on this picture:

![AES-CBC](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)

The vulnerability is that IVs used for encryption are predictable. Thus we can get an oracle that tells us if some guess `m[i]` is the plaintext corresponding to ciphertext block `c[i]`.

Indeed, to do that given a predictable next IV `IV`, we give `P ^ IV ^ c[i-1]` to encrypt.
This gives back to us the ciphertext `IV || AES(IV ^ P ^ IV ^ c[i-1]) || enc_padding`.

Thus the second block of the returned ciphertext is `AES(P ^ c[i-1])` and is equal to `c[i]` if and only if `P = m[i]`.

## Solution

For our purpose, we can first try out all 16 possible paddings.
To do so, we know the end of the string given the format: `", "user":"Alice","cid":10}`.
Then we add our candidate padding, take out the last 16 characters to form a block and test the padding.

```python
from pwn import *
from Crypto.Util.strxor import strxor

CTXT = bytes.fromhex("61499b3f31cee611a72eaf3cbfcf7d1cebb228a44db94e7b0504c145fcf00e57d2e0b9e24c7259bbeebccd03c100a645f418f2f58cc073cc71f214eb64a3b20ddfb406f6ebbd6781119efe13116af3abfe52609961727213ea69b8f8f1e4298ed3a42bc9ae4b8f1785184153ee3e113a8c9d55ddec48c85c53d5aa4a4089e47c3026a0bdb4d5d2659e57c31a76cca407ea0a92430d8540b8ef677405e8c4b193")
N_BLOCKS = len(CTXT) // 16

def receive_iv():
    sh.recvuntil(b"IV for encryption (hex):\n")
    iv = bytes.fromhex(sh.recvline().decode())
    return iv

def oracle_encrypt(data):
    sh.recvuntil(b"Enter message (as a hex bytes string):\n")
    sh.sendline(data.hex())
    sh.recvuntil(b"Ciphertext (hex):")
    ctxt = sh.recvline().decode()
    return bytes.fromhex(ctxt)

def find_padding():
    end_string = b'"user":"Alice","cid":10}'
    last_block = CTXT[16*(N_BLOCKS-1):]
    previous_block = CTXT[16*(N_BLOCKS-2):16*(N_BLOCKS-1)]
    print(last_block)
    
    for i in range(1, 17):
        candidate_ptxt = end_string + bytes([i] * i)
        candidate_ptxt = candidate_ptxt[len(candidate_ptxt)-16:]
        current_iv = receive_iv()
        block_to_send = strxor(current_iv, strxor(previous_block, candidate_ptxt))
        candidate_ctxt = oracle_encrypt(block_to_send)[16:32]
        if candidate_ctxt == last_block:
            print("Found", i)
            return i
```

We find a padding of 16. 

This gives us the block format, with `|` separating the blocks:

```
| :"DG'hAck-{{b516 | 13f7}}","user":" | Alice","cid":10} | padding
```
At first, I thought the flag would be in the format `DGA{...}`, which would have been impossible to brute force as it would require too many characters possible.

That's why the flag is in a strange format, so we only have 4 characters at the same time to brute force (and we need to do it twice).

Here is for example how to brute force the first 4 characters:

```python
import itertools
alphabet = "0123456789abcdef"
C5 = CTXT[16*5:16*6]
C6 = CTXT[16*6:16*7]

def test(PTXT):
    current_iv = receive_iv()
    block_to_send = strxor(current_iv, strxor(C5, PTXT))
    candidate_ctxt = oracle_encrypt(block_to_send)[16:32]
    return candidate_ctxt == C6

for v in itertools.product(alphabet, repeat=4):
    plaintext = ':"DG' + "'" + 'hAck-{{' + '{}{}{}{}'.format(v[0], v[1], v[2], v[3])
    print(plaintext[12:])
    if test(plaintext.encode()):
        print("FOUND!!!")
        print(plaintext)
        break
```

We do this for each part of the flag and find it in less than 10 minutes.

Flag: `DG'hAck-{{e20eb967}}`