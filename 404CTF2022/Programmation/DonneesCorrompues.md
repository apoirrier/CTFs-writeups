# Données corrompues

> Bonjour, agent. Comme vous le savez, vous êtes dans une unité spécialisée dans la cybersécurité, mais vous n'êtes pas sans savoir que la programmation est un outil qui nous est très précieux et qui apparaît dans la plupart de nos tâches, ce qui explique l'utilité d'une section dédiée.
Pour votre première mission avec nous, vous aurez à décoder des données interceptées entre deux machines de Hallebarde. Il s'agit de base64 mais elle semble corrompue... nos experts en ont déjà décodé une partie, à vous de finir le travail. Retrouvez les informations qui ont été échangées.
>
> Format du flag : 404CTF{flag} avec flag en minuscules
>
> nc challenge.404ctf.fr 30117

## Description

Quand on se connecte sur la ressource donnée, on obtient le message suivant:

> Oulah, ces données semblent bien étranges ! Pouvez-vous les décoder pour nous ?
>
> Il faut nous renvoyer les octets sous forme binaire (avec les zéros inutiles), tout collé, sans aucun autre caractère !
>
> Un exemple qu'a réussi à reconstituer notre groupe d'experts :
>
> L'entrée : Rmх%hZуА*6KQ
>
> Doit donner en sortie : 01000110011011000110000101100111001000000011101000101001

Puis on nous donne la première des 250 données à convertir.

En revanche, quand j'essaie de décoder la chaîne de test avec `base64.b64decode`, j'obtiens le message d'erreur suivant:

```
Traceback (most recent call last):
  File "/usr/lib/python3.10/base64.py", line 37, in _bytes_from_decode_data
    return s.encode('ascii')
UnicodeEncodeError: 'ascii' codec can't encode character '\u0445' in position 2: ordinal not in range(128)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.10/base64.py", line 80, in b64decode
    s = _bytes_from_decode_data(s)
  File "/usr/lib/python3.10/base64.py", line 39, in _bytes_from_decode_data
    raise ValueError('string argument should contain only ASCII characters')
ValueError: string argument should contain only ASCII characters
```

Apparemment, l'un des caractère n'est pas de l'ASCII...
Je cherche sur internet le caractère unicode `\u0445`: il s'agit de la `Lettre minuscule cyrillique kha', qui ressemble à un x.

Je cherche donc également sur internet les lettres unicodes qui ressemblent à des caractères ASCII. J'apprends qu'il s'agit d'[homoglyphes](https://fr.wikipedia.org/wiki/Homoglyphe).

## Solution

L'idée est donc de convertir les chaînes en entrée en remplaçant chaque homoglyphe par son équivalent ASCII.

Pour ce faire, je télécharge une [liste d'homoglyphes](https://github.com/codebox/homoglyph/blob/master/raw_data/chars.txt).

Je la modifie à la main pour supprimer les lignes dont je n'ai pas besoin, les commentaires, et pour être sûr que le premier caractère de chaque ligne est ASCII.
Ma liste finale est [ici](ressources/homoglyphs.txt).

Puis je lance le code suivant:

```python
from pwn import *
from base64 import b64decode

# Replace every homoglyph with its ASCII equivalent
def normalize(corrompu):
    ret = ""
    for c in corrompu.decode():
        if c.isascii():
            ret = ret + c
        else:
            found = False
            with open("homoglyphs.txt", "rb") as f:
                for l in f:
                    if c in l.decode():
                        ret = ret + l.decode()[0]
                        found = True
                        break
            if not found:
                print("Error with " + c)
                exit(1)
    return ret

# replace homoglyphs, decode base 64 and encode to bits
# Also, save data in a file
def convert(corrompu):
    corrompu = corrompu.strip()
    b64 = normalize(corrompu)
    decoded = b64decode(b64 + 4*"=")
    with open("out", "ab") as f:
        f.write(decoded)
    return ''.join(format(byte, '08b') for byte in decoded)

sh = remote("challenge.404ctf.fr", 30117)

for i in range(250):
    sh.recvuntil("[")
    print("[" + sh.recvuntil(b"es : ").decode())
    corrompu = sh.recvline()
    converted = convert(corrompu)
    sh.sendline(converted.encode())
sh.interactive()
```

On obtient le message final suivant:

> Wouaouh, tu as réussi ! Tu peux maintenant utiliser ces données pour obtenir le flag ! Il suffit de les assembler... ;-)

On relance donc le programme en sauvegardant la donnée.
Il s'agit d'un fichier audio, où une voix automatisée nous dicte le flag.

Flag: `404CTF{l4_b4s3_64_3ff1c4c3_m41s_c4pr1c13us3}`