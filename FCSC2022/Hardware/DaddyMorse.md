# Daddy Morse

> Les télégraphes Morse permettaient d'échanger des messages de texte à longue distance, en encodant un message sous forme d'impulsions électriques. Le serveur se comporte comme un mini-télégraphe et décode les données que vous lui envoyez.
>
> Vous devez envoyer CAN I GET THE FLAG.
>
> Vous avez le code du serveur ainsi qu'un exemple de message à disposition.
>
> Les paramètres de transmission sont les suivants :
>
> fréquence d'échantillonage : 24kHz
>
> durée d'un . : 1 milliseconde
>
> durée d'un - : 5 millisecondes
>
> espacement entre deux lettres : 5 millisecondes
>
> espace entre deux mots : 20 millisecondes
>
> nc challenges.france-cybersecurity-challenge.fr 2251

## Solution

By analysing the hellow world example, I can see that what is sent are either 0 or 1+j.

So I assume that there are two states up and down, and proceed according to the given instructions.

```python
from pwn import *
import numpy as np
import matplotlib.pyplot as plt
import base64

freq = 24000

def point(tab):
    for _ in range(freq // 1000):
        tab.append(1)
    for _ in range(freq // 1000):
        tab.append(0)

def dash(tab):
    for _ in range(5* freq // 1000):
        tab.append(1)
    for _ in range(freq // 1000):
        tab.append(0)

def next_letter(tab):
    for _ in range(4 * freq // 1000):
        tab.append(0)

def next_word(tab):
    for _ in range(19 * freq // 1000):
        tab.append(0)

def sentence_to_morse(sentence):
    tab = []
    for c in sentence:
        if c == '.':
            point(tab)
        elif c == '-':
            dash(tab)
        elif c == ' ':
            next_letter(tab)
        else:
            next_word(tab)
    return tab

HOST = args.HOST or "challenges.france-cybersecurity-challenge.fr"
PORT = args.PORT or  2251

c = remote(HOST, PORT)

hello_signal = np.fromfile("signal.iq", dtype = np.complex64)
print(hello_signal[0])
hello_converted = sentence_to_morse("-.-. .- -./../--. . -/- .... ./..-. .-.. .- --.")
hello_signal = (1+1j) * np.array(hello_converted, dtype = np.complex64)


encoded_signal = base64.b64encode(hello_signal.tobytes())

c.recvuntil(b"> ")
c.sendline(encoded_signal)
print(c.recvline())
```

Flag: `FCSC{e8b4cad7d00ca921eb12824935eea3b919e5748264fe1c057eef4de6825ad06c}`