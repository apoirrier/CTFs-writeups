# La fonte des hashs

> Nos experts ont réussi à intercepter un message de Hallebarde : 
>
> 18f2048f7d4de5caabd2d0a3d23f4015af8033d46736a2e2d747b777a4d4d205
>
> Malheureusement il est haché ! L'équipe de rétro-ingénierie vous a laissé cette note :
>
> > Voici l'algorithme de hachage. Impossible de remonter le haché mais vous, vous trouverez peut être autre chose. Voici comment lancer le hachage : python3 hash.py [clair]
> >
> > PS : Les conversations interceptées parlaient d'algorithme "très frileux" ...

## Description

On nous donne le code Python suivant:

```python
import base64, codecs
magic = 'IyEvdXNyL2Jpbi9weXRob24KIyAtKi0gY29kaW5nOiB1dGYtOCAtKi0KaW1wb3J0IHN5cwoKCgojIGZyb20gaHR0cHM6Ly9hc2VjdXJpdHlzaXRlLmNvbS9zdWJqZWN0cy9jaGFwdGVyODgKc2JveCA9IFsnMDExMDAwMTEnLCAnMDExMTExMDAnLCAnMDExMTAxMTEnLCAnMDExMTEwMTEnLCAnMTExMTAwMTAnLCAnMDExMDEwMTEnLCAnMDExMDExMTEnLCAnMTEwMDAxMDEnLCAnMDAxMTAwMDAnLCAnMDAwMDAwMDEnLCAnMDExMDAxMTEnLCAnMDAxMDEwMTEnLCAnMTExMTExMTAnLCAnMTEwMTAxMTEnLCAnMTAxMDEwMTEnLCAnMDExMTAxMTAnLCAnMTEwMDEwMTAnLCAnMTAwMDAwMTAnLCAnMTEwMDEwMDEnLCAnMDExMTExMDEnLCAnMTExMTEwMTAnLCAnMDEwMTEwMDEnLCAnMDEwMDAxMTEnLCAnMTExMTAwMDAnLCAnMTAxMDExMDEnLCAnMTEwMTAxMDAnLCAnMTAxMDAwMTAnLCAnMTAxMDExMTEnLCAnMTAwMTExMDAnLCAnMTAxMDAxMDAnLCAnMDExMTAwMTAnLCAnMTEwMDAwMDAnLCAnMTAxMTAxMTEnLCAnMTExMTExMDEnLCAnMTAwMTAwMTEnLCAnMDAxMDAxMTAnLCAnMDAxMTAxMTAnLCAnMDAxMTExMTEnLCAnMTExMTAxMTEnLCAnMTEwMDExMDAnLCAnMDAxMTAxMDAnLCAnMTAxMDAxMDEnLCAnMTExMDAxMDEnLCAnMTExMTAwMDEnLCAnMDExMTAwMDEnLCAnMTEwMTEwMDAnLCAnMDAxMTAwMDEnLCAnMDAwMTAxMDEnLCAnMDAwMDAxMDAnLCAnMTEwMDAxMTEnLCAnMDAxMDAwMTEnLCAnMTEwMDAwMTEnLCAnMDAwMTEwMDAnLCAnMTAwMTAxMTAnLCAnMDAwMDAxMDEnLCAnMTAwMTEwMTAnLCAnMDAwMDAxMTEnLCAnMDAwMTAwMTAnLCAnMTAwMDAwMDAnLCAnMTExMDAwMTAnLCAnMTExMDEwMTEnLCAnMDAxMDAxMTEnLCAnMTAxMTAwMTAnLCAnMDExMTAxMDEnLCAnMDAwMDEwMDEnLCAnMTAwMDAwMTEnLCAnMDAxMDExMDAnLCAnMDAwMTEwMTAnLCAnMDAwMTEwMTEnLCAnMDExMDExMTAnLCAnMDEwMTEwMTAnLCAnMTAxMDAwMDAnLCAnMDEwMTAwMTAnLCAnMDAxMTEwMTEnLCAnMTEwMTAxMTAnLCAnMTAxMTAwMTEnLCAnMDAxMDEwMDEnLCAnMTExMDAwMTEnLCAnMDAxMDExMTEnLCAnMTAwMDAxMDAnLCAnMDEwMTAwMTEnLCAnMTEwMTAwMDEnLCAnMDAwMDAwMDAnLCAnMTExMDExMDEnLCAnMDAxMDAwMDAnLCAnMTExMTExMDAnLCAnMTAxMTAwMDEnLCAnMDEwMTEwMTEnLCAnMDExMDEwMTAnLCAnMTEwMDEwMTEnLCAnMTAxMTExMTAnLCAnMDAxMTEwMDEnLCAnMDEwMDEwMTAnLCAnMDEwMDExMDAnLCAnMDEwMTEwMDAnLCAnMT'
love = 'RjZQRkZGRaYPNaZGRjZGNjZQNaYPNaZGRkZQRkZGRaYPNaZGNkZQRjZGNaYPNaZGRkZGRjZGRaYPNaZQRjZQNjZGRaYPNaZQRjZQRkZQRaYPNaZQNkZGNjZGRaYPNaZGNjZQNkZQRaYPNaZQRjZQNkZQRaYPNaZGRkZGRjZQRaYPNaZQNjZQNjZGNaYPNaZQRkZGRkZGRaYPNaZQRjZGNjZQNaYPNaZQNkZGRkZQNaYPNaZGNjZGRkZGRaYPNaZGNkZQRjZQNaYPNaZQRjZGNjZQRaYPNaZGNkZQNjZGRaYPNaZQRjZQNjZQNaYPNaZGNjZQRkZGRaYPNaZGNjZGNjZGNaYPNaZGNjZGRkZQRaYPNaZQNkZGRjZQNaYPNaZGRkZGNkZQRaYPNaZGNkZGRkZQNaYPNaZGNkZGNkZGNaYPNaZGRjZGRjZGNaYPNaZQNkZQNjZQRaYPNaZQNjZGNjZQNaYPNaZGRkZGRkZGRaYPNaZGRkZGNjZGRaYPNaZGRjZGNjZGNaYPNaZGRjZQRkZQRaYPNaZQNjZQRkZQNaYPNaZQNjZGNjZGRaYPNaZGRkZQRkZQNaYPNaZQRjZGRkZGRaYPNaZGNjZGNkZGRaYPNaZQRjZQNkZQNaYPNaZQNjZGNkZGRaYPNaZGRjZQNkZQNaYPNaZGNkZQNkZGRaYPNaZQRkZGRkZGNaYPNaZQNkZGRkZQRaYPNaZQRkZQNkZQNaYPNaZQRjZGRkZQRaYPNaZQNjZGRjZQRaYPNaZQRkZGNjZGRaYPNaZQRkZQNjZQNaYPNaZGNjZQNjZQRaYPNaZQRjZQRkZGRaYPNaZGRjZGRkZQNaYPNaZQNkZQNjZGNaYPNaZQNkZQRjZGNaYPNaZGNjZGNjZQNaYPNaZGNjZQRjZQNaYPNaZQRjZQNkZGNaYPNaZGRkZQRkZGNaYPNaZGNkZGRjZQNaYPNaZQNjZGNkZQNaYPNaZGRjZGRkZGNaYPNaZQRjZGRkZGNaYPNaZQNjZQRjZGRaYPNaZGRjZGRjZGRaYPNaZGRkZQNjZQNaYPNaZQNkZGNjZGNaYPNaZQNkZGRjZGNaYPNaZQNjZQRjZGNaYPNaZQRjZQRjZQRaYPNaZQNjZQNkZGNaYPNaZQNkZQNkZQNaYPNaZQRjZGRkZQNaYPNaZGRjZQNjZGNaYPNaZGRjZGNjZGRaYPNaZGNkZQRkZQNaYPNaZQRkZQNjZGNaYPNaZGNjZGNjZQRaYPNaZGNjZGNkZQRaYPNaZGRkZQNkZQNaYPNaZQRkZGRjZQRaYPNaZGRkZQNkZGRaYPNaZGRjZQRjZQNaYPNaZQNkZGNkZGRaYPNaZQRkZQRkZQRaYPNaZGNjZQRkZQRaYPNaZGRjZGNkZQRaYPNaZQRjZQRkZGNaYPNaZGNkZQRjZQRaYPNaZQRkZQRkZQNaYPNaZQRjZGNkZGNaYPNaZGRkZGNkZQNaYPNaZGRkZQRjZGNaYPNaZQRkZQNkZQRaYPNaZQRkZGRjZGNaYPNaZGNkZQRkZGNaYPNaZQNjZQRjZQNaYPNaZGNkZGRjZGNaYPNaZQRkZGRjZQNaYPNaZQNkZQNkZQRaYPNaZQNkZQRkZGNaYPNaZQNjZGRkZQNaYPNaZGNkZQNkZGNaYPNaZGNkZGNkZQNaYPNaZGRjZQNkZGNaYPNa'
god = 'MTExMDEwMDAnLCAnMTEwMTExMDEnLCAnMDExMTAxMDAnLCAnMDAwMTExMTEnLCAnMDEwMDEwMTEnLCAnMTAxMTExMDEnLCAnMTAwMDEwMTEnLCAnMTAwMDEwMTAnLCAnMDExMTAwMDAnLCAnMDAxMTExMTAnLCAnMTAxMTAxMDEnLCAnMDExMDAxMTAnLCAnMDEwMDEwMDAnLCAnMDAwMDAwMTEnLCAnMTExMTAxMTAnLCAnMDAwMDExMTAnLCAnMDExMDAwMDEnLCAnMDAxMTAxMDEnLCAnMDEwMTAxMTEnLCAnMTAxMTEwMDEnLCAnMTAwMDAxMTAnLCAnMTEwMDAwMDEnLCAnMDAwMTExMDEnLCAnMTAwMTExMTAnLCAnMTExMDAwMDEnLCAnMTExMTEwMDAnLCAnMTAwMTEwMDAnLCAnMDAwMTAwMDEnLCAnMDExMDEwMDEnLCAnMTEwMTEwMDEnLCAnMTAwMDExMTAnLCAnMTAwMTAxMDAnLCAnMTAwMTEwMTEnLCAnMDAwMTExMTAnLCAnMTAwMDAxMTEnLCAnMTExMDEwMDEnLCAnMTEwMDExMTAnLCAnMDEwMTAxMDEnLCAnMDAxMDEwMDAnLCAnMTEwMTExMTEnLCAnMTAwMDExMDAnLCAnMTAxMDAwMDEnLCAnMTAwMDEwMDEnLCAnMDAwMDExMDEnLCAnMTAxMTExMTEnLCAnMTExMDAxMTAnLCAnMDEwMDAwMTAnLCAnMDExMDEwMDAnLCAnMDEwMDAwMDEnLCAnMTAwMTEwMDEnLCAnMDAxMDExMDEnLCAnMDAwMDExMTEnLCAnMTAxMTAwMDAnLCAnMDEwMTAxMDAnLCAnMTAxMTEwMTEnLCAnMDAwMTAxMTAnXQoKCgoKZGVmIHN0cmluZzJiaXRzKHM9JycpOgogICAgdG1wID0gW10KICAgIGZvciB4IGluIHMgOgogICAgICAgIGJ5dGUgPSBiaW4ob3JkKHgpKVsyOl0KICAgICAgICBpZiBsZW4oYnl0ZSkgPiA4OgogICAgICAgICAgICBpbmRpY2VzID0gW2kgZm9yIGkgaW4gcmFuZ2UoMCwgbGVuKGJ5dGUpLCA4KV0KICAgICAgICAgICAgcGFydHMgPSBbIiIuam9pbihieXRlW2k6al0pLnpmaWxsKDgpIGZvciBpLGogaW4gemlwKGluZGljZXMsIGluZGljZXNbMTpdK1tOb25lXSldCiAgICAgICAgICAgIHRtcCArPSAocGFydHMpCiAgICAgICAgZWxzZSA6CiAgICAgICAgICAgIGJ5dGUgPSBieXRlLnpmaWxsKDgpCiAgICAgICAgICAgIHRtcC5hcHBlbmQoYnl0ZSkKICAgIHJldHVybiB0bXAKCmRlZiBwYWRkaW5nKGJpbmFyeSk6CiAgICBpZigobGVuKGJpbmFyeSkgKyAxICkgJSAzMiA9PSAwKToKICAgICAgICBiaW5hcnkuYXBwZW5kKCcwMDAwMDAwMScpCiAgICAgICAgYmluYXJ5LmFwcGVuZCgnMDAwMDAwMDAnKQogICAgaWYobGVuKGJpbmFyeSklMzIgIT0gMCBvciBsZW4oYmluYXJ5KSA9PSAwKToKICAgICAgICBiaW5hcnkuYXBwZW5kKCcwMD'
destiny = 'NjZQNjZFpcPvNtVPNtVPNtq2ucoTHtoTIhXTWcozSlrFxyZmVtVG0tZQbXVPNtVPNtVPNtVPNtLzyhLKW5YzSjpTIhMPtaZQNjZQNjZQNaXDbXMTIzVUuipvuuYTVcBtbtVPNtpzImVQ0tVvVXVPNtVTMipvOcVTyhVUWuozqyXTkyovuuXFx6PvNtVPNtVPNtVPNtVUWyplNeCFOmqUVbnJ50XTSonI0cVS4tnJ50XTWonI0cXDbtVPNtpzI0qKWhVUWypjbXMTIzVUAvo3uso3OyXTWcozSlrFx6PvNtVPOzo3VtnFOcovOlLJ5aMFufMJ4bLzyhLKW5XFx6PvNtVPNtVPNtnJ5xMKttCFOcoaDbLzyhLKW5J2yqYQVcPvNtVPNtVPNtLzyhLKW5J2yqVQ0tp2WirSgcozEyrS0XPzEyMvOjnTSmMGRbLzyhLKW5XGbXVPNtVT0tCFOcoaDboTIhXTWcozSlrFxtYlNmZvxXVPNtVUEgpPN9VSgqPvNtVPOzo3VtnFOcovOlLJ5aMFtjYPOfMJ4bLzyhLKW5XFjtoFx6PvNtVPNtVPNtqT1jYzSjpTIhMPu4o3VbLzyhLKW5J2yqYPOvnJ5upayonFfkKFxcPvNtVPOlMKE1pz4tqT1jPtcxMJLtpTuup2HlXTWcozSlrFx6PvNtVPOzo3VtnFOcovOlLJ5aMFtkYTkyovuvnJ5upaxcXGbXVPNtVPNtVPOzo3VtnvOcovOlLJ5aMFucXGbXVPNtVPNtVPNtVPNtLzyhLKW5J2yqVQ0trT9lXTWcozSlrIgcKFjtLzyhLKW5J2cqXDbXMTIzVTWcqUZlnTI4XTWcozSlrFx6PvNtVPObMKusp3ElVQ0tVvVXVPNtVTMipvOvnKDtnJ4tLzyhLKW5BtbtVPNtVPNtVTuyrS9mqUVtXm0tMz9loJS0XTyhqPuvnKDfVQVcYPNaZQW4WlxXVPNtVUWyqUIlovObMKusp3ElPtcxMJLtnPugXGbXVPNtVUOfLJyhVQ0toDbtVPNtLzyhLKW5VQ0tp3ElnJ5aZzWcqUZbpTkunJ4cPvNtVPOjLJExnJ5aXTWcozSlrFxXVPNtVTyzVTkyovuvnJ5upaxcVQ4tZmV6PvNtVPNtVPNtLzyhLKW5VQ0tpTuup2HkXTWcozSlrFxXVPNtVUObLKAyZvuvnJ5upaxcPvNtVPOjnTSmMGVbLzyhLKW5XDbtVPNtpTuup2HlXTWcozSlrFxXVPNtVUAvo3uso3OyXTWcozSlrFxXVPNtVTuup2usp3ElVQ0tLzy0pmWbMKtbLzyhLKW5XDbtVPNtpzI0qKWhVTuup2usp3ElPtbXpTkunJ4tCFNtVvVXnJLtoTIhXUA5pl5upzq2XFN9CFNkBtbtVPNtpUWcoaDbVxS1L3IhVTSlM3IgMJ50VTEioz7QdF4tHzyyovQQbPObLJAbMKVhVRW5MFOvrJHhVvxXMJkcMvOfMJ4bp3ymYzSlM3LcVQ49VQVtBtbtVPNtpTkunJ4tXm0tp3ymYzSlM3MoZI0XVPNtVTMipvOcVTyhVUWuozqyXQVfoTIhXUA5pl5upzq2XFx6PvNtVPNtVPNtpTkunJ4tXm0tVvNvVPftp3ElXUA5pl5upzq2J2yqXDbtVPNtpUWcoaDbnPujoTScovxcPt=='
joy = '\x72\x6f\x74\x31\x33'
trust = eval('\x6d\x61\x67\x69\x63') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x6c\x6f\x76\x65\x2c\x20\x6a\x6f\x79\x29') + eval('\x67\x6f\x64') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x64\x65\x73\x74\x69\x6e\x79\x2c\x20\x6a\x6f\x79\x29')
eval(compile(base64.b64decode(eval('\x74\x72\x75\x73\x74')),'<string>','exec'))
```

Il s'agit d'un code obfusqué, mais on peut facilement retrouver le code source en remplaçant la dernière ligne par un print:

```python
print(base64.b64decode(eval('\x74\x72\x75\x73\x74')).decode())
```

On peut maintenant analyser le code source. La fonction de hachage est la suivante:

```python
def sbox_ope(binary):
    for i in range(len(binary)):
        index = int(binary[i],2)
        binary[i] = sbox[index]

def phase1(binary):
    m = int(len(binary) / 32)
    tmp = []
    for i in range(0, len(binary), m):
        tmp.append(xor(binary[i], binary[i+1]))
    return tmp

def phase2(binary):
    for i in range(1,len(binary)):
        for j in range(i):
            binary[i] = xor(binary[i], binary[j])

def h(m):
    plain = m
    binary = string2bits(plain)
    padding(binary)
    if len(binary) > 32:
        binary = phase1(binary)
    phase2(binary)
    phase2(binary)
    phase2(binary)
    sbox_ope(binary)
    hash_str = bits2hex(binary)
    return hash_str
```

Elle est composée de deux phases:
- une phase de compression avec la fonction `phase1` qui xor les blocks de 32 bytes pour n'en avoir plus qu'un;
- une phase de substitution et transpositions avec les fonctions `phase2` et `sbox_ope`.

Avec un peu de chance, le flag fait moins de 32 caractères, et donc la phase de compression ne fait rien, et on peut peut être inverser la seconde phase.

## Solution

J'ai donc choisi d'inverser chaque sous-fonction une par une.

Pour commencer, la fonction `sbox_ope` remplace chaque byte `b` par `sbox[b]`, on cherche donc les antécédents par `sbox`.
Ici, on espère que le tableau soit injectif, et donc on prend juste la première valeur.

```python
def rev_sbox(binary):
    tmp = []
    for i in range(len(binary)):
        idx = sbox.index(binary[i])
        tmp.append(bin(idx)[2:].zfill(8))
    return tmp
```

Inverser la fonction `phase2` revient à effectuer les mêmes opérations XOR dans l'ordre inverse:

```python
def rev2(binary):
    for i in range(len(binary)-1,0,-1):
        for j in range(i):
            binary[i] = xor(binary[i], binary[j])
```

J'ajoute aussi une fonction d'aide pour convertir l'héxadécimal en binaire:

```python
def hex2bits(s):
    binary = []
    for i in range(0,len(s),2):
        binary.append(bin(int(s[i:i+2], 16))[2:].zfill(8))
    return binary
```

Avec tout cela, on peut inverser la fonction de hachage !

```python
binary = hex2bits(h)
binary = rev_sbox(binary)
rev2(binary)
rev2(binary)
rev2(binary)

origin = [chr(int(x,2)) for x in binary]
print("".join(origin))
```

Flag: `404CTF{yJ7dhDm35pLoJcbQkUygIJ}`