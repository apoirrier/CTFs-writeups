# Mise à jour

Ce challenge est composé de deux parties indépendantes mais ayant un thème similaire.

## Mise à jour requise

> Notre service de renseignement nous a informé qu'un agent de Hallebarde avait une curieuse façon de gérer la sécurité de ses fichiers. Il semblerait qu'il s'agisse d'un fan inconditionnel de Python au point de l'utiliser pour gérer ses mots de passe! Nous avons réussi à intercepter une partie du code source qui gère la vérification du mot de passe maître.
>
> Votre mission est de trouver ce mot de passe. Attention cependant, il semblerait que notre pythonesque ami ait utilisé des syntaxes spécifiques à Python3.10, j'espère que cela ne vous posera pas de problèmes!
>
> Bonne chance à vous!

On nous donne le code suivant:

```python
#!/usr/bin/python3.10
import random as rd

s = [16, 3, 12, 9, 1, 60, 1, 3, 14, 39, 13, 16, 16, 1, 9, 13, 3, 39, 60,
    16, 16, 1, 60, 7, 39, 13, 3, 13, 18, 3, 13, 25, 14, 3, 1, 14, 60,
    13, 32, 13, 3, 39, 16, 18, 18, 3, 43, 16, 18, 3, 1, 43, 18, 16,
    13, 16, 1, 3, 1, 16, 13, 18, 60, 16, 3, 3, 14, 18, 13, 14, 16, 18,
    7, 3, 7, 25, 7, 7, 13, 13, 13, 3, 60, 1, 3, 13, 1, 25, 18, 16, 32,
    16, 60, 1, 7, 44, 18, 39, 39, 39, 60, 3, 1, 60, 3, 16, 13, 13, 14,
    1, 3, 39, 39, 31, 32, 39, 32, 18, 39, 3, 13, 32, 60, 7, 7, 39, 14,
    3, 18, 14, 60, 39, 18, 7, 1, 32, 13, 3, 14, 39, 39, 7, 1, 1, 13,
    29, 60, 13, 39, 14, 14, 16, 60, 1, 3, 44, 14, 3, 1, 1, 1, 39, 13,
    14, 39, 18, 3, 7, 13, 39, 32, 1, 43, 1, 16, 1, 3, 18, 14, 25, 32,
    7, 13, 39, 7, 1, 3, 60, 13, 13, 7, 18, 1, 3, 18, 1, 60, 7, 1, 39,
    14, 3, 39, 7, 31, 1, 7, 18, 7, 32, 3, 3, 14, 32, 14, 1, 32, 12,
    18, 31, 39, 1, 13, 13, 43, 44, 32, 3, 32, 60, 14, 60, 60, 7, 3, 1,
    3, 3, 14, 1, 60, 16, 44, 3, 1, 32, 13, 5, 16, 39, 3, 60, 7, 14, 3,
    13, 7, 31, 13, 39, 9, 3, 44, 13, 16, 14, 18, 18, 3, 7, 3, 3, 3, 7,
    3, 3, 16, 39, 3, 3, 13, 32, 13, 3, 18, 7, 10, 3, 18, 1, 7, 7, 18,
    13, 43, 18, 3, 32, 39, 32, 13, 1, 18, 10, 1, 32, 1, 16, 32, 3, 44,
    3, 18, 1, 1, 1, 16, 18, 25, 60, 1, 39, 1, 18, 60, 16, 1, 7, 3, 13,
    16, 18, 39, 14, 7, 14, 3, 14, 13, 7, 16, 10, 18, 13, 3, 16, 13, 3,
    32, 43, 13, 14, 1, 13, 1, 14, 18, 60, 7, 3, 7, 31, 1, 18, 26, 7,
    3, 3, 32, 1, 7, 18, 7, 1, 16, 18, 39, 14, 7, 3
]

##
def a(c, r=True):
    n = ord(c)
    if r: rd.seed(n)
    match n:
        case 0:
            return dict.fromkeys(range(10), 0)
        case _:
            return (d:=a(chr(n - 1), False)) | {(m:=rd.randint(0, 9)): d[m] + rd.randint(0,2)}

##

def b(p, n):
    match list(p):
        case []:
            return []
        case [f, *rest]:
            l = list(a(f).values()) + b(''.join(rest), n*2)
            rd.seed(n)
            rd.shuffle(l)
            return l

##
def c(p, n=0):
    match p:
        case []:
            return n!=0
        case [f, *rest]:
            rd.seed(s[n])
            return rd.randint(0,30) == f and c(rest, n + 1)
##
if c(b(input("password:"), 1)):
    print("Utilise ce mot de passe pour valider le challenge!")
else:
    print("Essaye Encore!")
```

### Description

Notre mot de passe va passer par deux fonctions `c` et `b`, la fonction `b` va transformer notre mot de passe et la fonction `c` vérifie si la transformation est valide.

`c` est la version récursive du code itératif suivant:

```python
ret = True
for n in range(len(p)):
    rd.seed(s[n])
    ret = ret and rd.randint(0,30) == p[n]
```

On veut donc que pour tout `n`, `rd.randint(0,30) == p[n]` quand la seed `s[n]` est utilisée, ce qui nous donne immédiatement la valeur de `p` qui donne un flag valide.

On veut ensuite inverser `b` pour que la fonction `b` donne le bon `p`.

Remarquons la dernière étape effectuée par `b`: `l` vaut `list(a(f).values())` suivi d'une série de nombres, et ensuite `l` est mélangée par une permutation qu'on connaît (on sait que la seed vaut 1).

Par conséquent, connaissant le `p` qu'on souhaite avoir, on peut lui appliquer la transformation inverse, et trouver un `f` tel que `list(a(f).values())` coïncide avec le début du tableau obtenu.

On pourra ensuite effectuer la même chose pour les caractères suivants.

### Solution

On effectue d'abord deux calculs: trouver le `p` à atteindre, et pour chaque caractère `f` possible, on calcule son `list(a(f).values())` correspondant.

Ensuite, on applique les permutations inverses et on trouve ainsi le flag caractère par caractère.

```python
from chall import *

all_encoding = {}
for i in range(128):
    all_encoding[str(list(a(chr(i)).values()))] = chr(i)

p = []
for n in range(len(s)):
    rd.seed(s[n])
    p.append(rd.randint(0,30))

n = 1
flag = ""
for i in range(len(s)//10):
    x = list(range(len(s)-10*i))
    rd.seed(n)
    n *= 2
    rd.shuffle(x)
    p = [p[x.index(i)] for i in range(len(x))]
    flag += all_encoding[str(p[:10])]
    p = p[10:]

print(flag)
```

Flag: `404CTF{M3RC1_PY7H0N3.10_P0UR_L3_M47CH}`.


## Pas de MaJ

> Le fan de Python de Hallebarde est de retour! Mais il ne veut plus que tout le monde puisse lire ses codes sources...

On nous donne un fichier `pyc` à reverse.

Pour ce faire, j'utilise un [décompilateur](https://github.com/zrax/pycdc) qui est normalement compatible avec Python 3.10.

On obtient le code suivant:

```python
# Source Generated with Decompyle++
# File: chall.pyc (Python 3.10)

userInput = (lambda .0: [ ord(e) for e in .0 ])(input('Password:'))
key = 'd1j#H(&Ja1_2 61fG&'

def code(l):
Unsupported opcode: MATCH_SEQUENCE
    pass
# WARNING: Decompyle incomplete

if code(userInput) == [
    292,
    194,
    347,
    382,
    453,
    276,
    577,
    434,
    183,
    295,
    318,
    196,
    482,
    325,
    412,
    502,
    396,
    402,
    328,
    194,
    473,
    490,
    299,
    503,
    386,
    215,
    263,
    211,
    318,
    206,
    533]:
    print('Bravo!')
    return None
None('Dommage...')
```

Malheureusement, il semblerait que l'opcode `MATCH_SEQUENCE` ne soit pas supporté par la bibliothèque, malgré l'affirmation que Python 3.10 est supporté...

Ce n'est cependant pas grave, au vu des paramètres, on comprend qu'il faut que notre input, transformé par la fonction `code` donne la tableau.

Par ailleurs, je suppose comme il s'agit d'un switch case que le code transforme les caractères un à un, et par conséquent je tente le bruteforce suivant, caractère par caractère:

```python
from chall import code

objective = [292, 194, 347, 382, 453, 276, 577, 434, 183, 295, 318, 196, 482, 325, 412, 502, 396, 402, 328, 194, 473, 490, 299, 503, 386, 215, 263, 211, 318, 206, 533]

current = [0] * len(objective)
for i in range(len(current)):
    for c in range(128):
        current[i] = c
        if code(current)[i] == objective[i]:
            break

print("".join([chr(x) for x in current]))
```

Je trouve ainsi le flag.

Flag: `404CTF{R34D1NG_PYTH0N_BYT3C0D3}`.