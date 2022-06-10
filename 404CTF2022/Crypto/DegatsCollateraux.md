# Dégâts collatéraux

> Bonjour Agent,
>
> Nous avons réussi à infiltrer une connexion sécurisée d'Hallebarde via une attaque MITM. Malheureusement, cette connexion est chiffrée via un protocole qui semble très similaire à PGP, et même si nous avons un certain contrôle sur les informations qui transitent, nous n'avons pas réussi à exploiter notre position. Nous vous avons résumé tout ce que nous avons compris du fonctionnement de cette session dans le fichier ci-joint. Il nous manque quelques détails, mais il doit être presque complet. Voyez si vous pouvez faire quelque chose !

## Description

Nous sommes en position de MitM entre deux interlocuteurs: un émetteur et un oracle.

L'émetteur et l'oracle partagent une paire clé privée/publique `(x, y)` avec `y = g^x [p]` où g est un générateur de (Z/pZ)* et x a 1024 bits.

On nous fournit les paramètres publics `(g, p, y)`.

L'émetteur encrypte le flag avec AES-CBC en utilisant une clé et IV dérivés de `x`, et on nous fournit ce ciphertext `enc`.

Ensuite, l'émetteur peut envoyer des messages "à la PGP" à l'oracle:
- il choisit une `session_key` telle que `session_key` ait 16 bytes et `sum(session_key) % 31 == 0`.
- il encrypte le flag avec AES-CBC (avec un IV inconnu partagé avec l'oracle) en utilisant `session_key` comme clé: on obtient le chiffré `cipher`, qui ne nous est pas donné.
- il encrypte `session_key` avec le chiffrement d'El-Gamal. Le chiffré `ciphered_key` ne nous est pas donnée non plus.

L'émetteur envoie alors `(g,p,y), cipher, ciphered_key`, et nous pouvons modifier les paramètres publics et `ciphered_key`.

A noter que ce scénario ne fait aucun sens cryptographiquement parlant : pourquoi l'émetteur et l'oracle partagent la clé privée et non la clé publique, alors que c'est sensé être une donnée publique ? Et s'il y a partage d'information au préalable, pourquoi donc utiliser de la cryptographie asymétrique ?

L'oracle reçoit notre requête (potentiellement modifiée), et effectue la fonction suivante :

```python
def oracle( pubkey, privkey, cipher, ciphered_key ):
    g, p, y = pubkey
    if p.bit_length() != 2049:
        return "Erreur: le module ne fait pas 2049 bits"
    c0, c1 = ciphered_key
    try:
        key2 = EGDecrypt(c0, c1, g, p, privkey)
    except:
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    if not (is_session_key_valid(key2)):
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    # Il semble qu'arrivé ici le serveur qui gère l'oracle lance d'autres fonctions / processus, mais nous n'avons pas
    # pu déterminer quoi
    aes = AES.new(key2, AES.MODE_CBC, iv=iv)
    try:
        pt = unpad(aes.decrypt(cipher), 16)
    except:
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    if pt != flag:
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    return "Le fichier est intact!"
```

Et c'est ici que nous pouvons effectuer une différentiation: au niveau du commentaire, le serveur devient beaucoup plus lent (réponse en 1s environ au lieu de quelques millisecondes).

J'ai pu découvrir cela en testant avec une `ciphered_key` loufoque et la véritable.
Avec la vraie clé, le temps de réponse est plus long.

Ainsi on peut déterminer avec certitude si l'oracle atteint le commentaire ou non.

## Solution

Le but ici est de retrouver chaque bit de la clé `x` un par un.

La fonction `EGDecrypt` est la suivante:

```python
def EGDecrypt( c0, c1, g, p, x ):
    m1 = (c1 * pow(c0, -x, p)) % p
    m = unpad(long_to_bytes(m1), 16)
    return m
```

Ainsi, l'oracle effectue le calcul `c1 * c0 ^ (-x) [p]` et vérifie si:
- le résultat est correctement bourré (padding correct);
- le texte clair est une `session_key` valide.

Si ces deux conditions sont réunies, on atteint le commentaire (et donc on a un temps long), sinon on a un temps court.

### Un exemple simple : retrouver le bit 0

Ceci nous permet de trouver le bit 0 de la clé très facilement.

En effet, choisissons `c0 = -1`.
Alors si le bit 0 de `x` est 0, c0 ^ (-x) va valoir 1, tandis que si le bit est 1,  c0 ^ (-x) va valoir -1.

Par conséquent, en choisissant `c1` une clé de session valide (qu'on aura correctement bourrée), on a `c1 * c0 ^ (-x) [p]` qui vaut `c1` si `x&1 == 0` et une clé invalide sinon.

Evaluer le temps de réponse de l'oracle nous permet donc de déterminer `x&1`:
- s'il est long, alors `x&1 == 0`;
- s'il est court, alors `x&1 == 1`.

### Généralisation

L'objectif est de généraliser l'observation ci-dessus afin de retrouver les 1024 bits de la clé.

Supposons qu'on ait trouvé les bits 0, ..., k-1 de `x`.
Alors de manière générale, on peut écrire:

```
x = 2^(k+1) * X + 2^k * b + x_known
```

où `X` est un entier, `b` est un bit et `x_known` est la partie de la clé que l'on connaît.

Comme pour le bit 0, je souhaite trouver `(c0, c1, p)` tel que `c1 * c0 ^ (-x) [p]` soit une clé valide si `b == 0` et invalide si `b == 1`.

Cela signifie que je souhaite trouver un `invc0 = c0^(-1)` d'ordre exactement `2^(k+1)`: cela permettrait d'avoir:

```
c0 ^ (-x) = invc0 ^ x = (invc0 ^ (2^(k+1)))^X * (invc0 ^ (2^k))^b * invc0^x_known
```

Ainsi, en choisissant `c1 = session_key * c0^x_known`, on obtient :

```
c1 * c0 ^ (-x) = session_key * (invc0 ^ (2^k))^b
```

Puique `invc0` est d'ordre `2^(k+1)`, `(invc0 ^ (2^k))^b == 1` si et seulement si `b == 0`.

### Choisir le bon groupe

Je veux trouver un groupe (Z/pZ)* ayant des éléments d'ordre `2^(k+1)` avec `0 <= k <= 1023`.

D'après le théorème de Lagrange, on sait que l'ordre de tout élément du groupe divide l'ordre du groupe.
Par ailleurs, l'ordre d'un groupe (Z/pZ)* est phi(p) (l'indicatrice d'Euler).
Mon objectif est de choisir un `p` tel que 2^1025 divise p.

Le premier groupe qui m'est venu à l'esprit est (Z/2^nZ)*, comme je sais que `phi(2^n) = 2^(n-1)`.

Malheureusement, ce groupe ne marche pas.
En effet, à cause du bourrage, `session_key` n'est pas inversible.

Par conséquent, avoir `x * y = x [p]` n'implique pas `y=1`...

Cela se traduit par le fait que pour certains bits, `c1 * c0 ^ (-x) [p] == session_key` quelle que soit la valeur de `b`, et donc on ne peut pas trouver le bit correct.

J'ai donc tenté de trouver un autre groupe: je sais que pour p premier, `phi(p) = p-1`.

Je cherche donc `p` premier tel que `p-1` soit divisible par 2^1025.

En fait je fais mieux que ça: je cherche `p` premier tel que `p - 1 = 2^1025 * q` avec `q` premier.

Si je choisis un générateur `e` de Z/pZ*, alors `e^q` sera d'ordre 2^1025.

## Algorithme final

J'ai donc l'algorithme suivant pour trouver la solution.

### Partie 1: trouver le groupe

```python
from Crypto.Util.number import getPrime, isPrime

p = 4
while not isPrime(p):
    p = 1 + (getPrime(1024) << 1025)
print(p)
print(p.bit_length())
q = (p-1) >> 1025
```

### Partie 2: précalculer les c0

```python
e = pow(3,q,p)
order = 1025

Nbits = 1024 # number of bits of the key

# precomputing the bases
c0_precomputed = [pow(e,-(1 << (order - i)),p) for i in range(1,Nbits+1)]
```

### Partie 3: choisir une session_key valide

```python
from session import *

sesskey = b""
while not is_session_key_valid(sesskey):
    sesskey = urandom(16)
sesskey = bytes_to_long(pad(sesskey, 16))
```

### Partie 4: retrouver la clé

```python
from pwn import *
import time

time_threshold = 0.5
def call_oracle(sh, p, c0, c1):
    sh.recvuntil(b">")
    sh.sendline("(1,{},1)".format(p).encode())
    sh.recvuntil(b">")
    sh.sendline("({}, {})".format(c0,c1).encode())
    sh.recvuntil(b">")
    sh.sendline(b"")
    t = time.time()
    sh.recvuntil(b"ue:\n")
    tot_time = time.time() - t
    if tot_time >= time_threshold:
        return 0 # long time so valid key so 0
    return 1

sh = remote("challenge.404ctf.fr", 30762)

sh.recvuntil(b"question:\n")
enc = sh.readline().decode()
print(enc)

# recover key bit by bit
known_key = 0
for k in range(Nbits):
    # the oracle will compute c1*c0^-x
    c0 = c0_precomputed[k]
    c1 = (sesskey * pow(c0, known_key, p)) % p

    b = call_oracle(sh, p, c0, c1)
    print(b, end="")
    known_key |= (b << k)
```

### Partie 5: enjoy

```python
print(decrypt_flag(enc, known_key))
```

Flag: `404CTF{KO_C_est_le_chaos_le_K_O_S_O_V_O_la_BO_en_VO_d_un_fleau_degats_collateraux.7r3s_b0nne_ch4ns0n_m415_c0mm3n7_4v3z_v0u5_7Rouv3_C3_53Cre7??}`