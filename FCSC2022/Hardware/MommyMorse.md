# Mommy Morse

> On vous demande d'envoyer un message en Morse avec une modulation de fréquence à deux états. Le codage choisi est que les . et - sont représentés par une porteuse pure à une fréquence de 5kHz, et les espacements sont représentés par une porteuse pure à une fréquence de 1kHz.
>
> Vous devez envoyer CAN I GET THE FLAG.
>
> Vous avez le code du serveur ainsi qu'un exemple de message à disposition.
>
> Les paramètres de transmission sont les suivants :
>
> fréquence d'échantillonage : 24kHz
>
> envoi d'un . : porteuse pure de fréquence 5kHz pendant 1 milliseconde
>
> durée d'un - : porteuse pure de fréquence 5kHz pendant 5 millisecondes
>
> espacement entre deux lettres : porteuse pure de fréquence 1kHz pendant 5 millisecondes
>
> espace entre deux mots : porteuse pure de fréquence 1kHz pendant 20 millisecondes
>
> nc challenges.france-cybersecurity-challenge.fr 2252

## Solution

This challenge is the same as [DaddyMorse](DaddyMorse.md), but instead of just signal up and down we need to encode it in a signal of 1 or 5 kHz.

This means that consecutive values in our numpy array are multiplied by `e^(2*pi*j*f)`.

```python
from audioop import add
from pwn import *
import numpy as np
import base64

freq = 24000
angle_5 = np.exp(1j*2*np.pi*5000/freq)
angle_1 = np.exp(1j*2*np.pi*1000/freq)

def point(tab):
    for _ in range(freq // 1000):
        tab.append(tab[-1]*angle_5)
    for _ in range(freq // 2000):
        tab.append(tab[-1]*angle_1)

def dash(tab):
    for _ in range(5* freq // 1000):
        tab.append(tab[-1]*angle_5)
    for _ in range(freq // 2000):
        tab.append(tab[-1]*angle_1)

def next_letter(tab):
    for _ in range(int(4.5 * freq // 1000)):
        tab.append(tab[-1]*angle_1)

def next_word(tab):
    for _ in range(int(19.5 * freq // 1000)):
        tab.append(tab[-1]*angle_1)

def sentence_to_morse(sentence):
    tab = [1]
    for c in sentence:
        if c == '.':
            point(tab)
        elif c == '-':
            dash(tab)
        elif c == ' ':
            next_letter(tab)
        else:
            next_word(tab)
    return np.array(tab, dtype = np.complex64)

from server import *

HOST = args.HOST or "challenges.france-cybersecurity-challenge.fr"
PORT = args.PORT or  2252

c = remote(HOST, PORT)

hello_signal = np.fromfile("signal.iq", dtype = np.complex64)

new_signal = sentence_to_morse("-.-. .- -./../--. . -/- .... ./..-. .-.. .- --.")
print(fm_decode(new_signal))


encoded_signal = base64.b64encode(new_signal.tobytes())

c.recvuntil(b"> ")
c.sendline(encoded_signal)
print(c.recvline())
```

Flag: `FCSC{490b88345a22d35554b3e319b1200b985cc7683e975969d07841cd56dd488649}`