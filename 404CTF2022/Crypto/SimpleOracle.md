# Un Simple Oracle

Ce challenge est en deux parties assez semblables.

## Partie 1

> Bonjour agent, Nous avons découvert un étrange service ouvert sur un des serveurs de Hallebarde. Il semble possible d'interagir avec lui. Pourrriez-vous récupérer son secret?
>
> nc challenge.404ctf.fr 32128

### Description

Quand on se connecte, on obtient le message suivant:

> Voici le message secret que je dois garder. Vous pouvez le voir, de toute façon vous ne pourrez rien en faire!
>
> [Un entier représentant le chiffré]
>
> J'en profite également pour noter quelques informations ici:
>
> N = [la valeur de N]
>
> e = 65537
>
> Ceci étant dit, passons à ce que vous vouliez me dire!

On peut ensuite entrer un entier et on obtient sa décryption.
Si on entre le chiffré donné, l'oracle refuse de décrypter.

### Solution

Nous avons affaire à un chiffrement RSA, ainsi si `d` est la clé privée, ce qui est calculé par l'oracle est `c^d [N]` où `c` est le chiffré que l'on fournit.

On n'a pas le droit de donner le chiffré du flag `c*`.

En revanche, on peut fournir `c = - c*` de telle sorte qu'on obtienne `m = (-c*)^d = -(c*^d) = -m*` puisque `d` est impair.

On peut donc exécuter le script suivant pour avoir le flag:

```python
from pwn import *
from Crypto.Util.number import long_to_bytes

sh = remote("challenge.404ctf.fr", 32128)
sh.recvuntil(b"faire!\n")
ctxt = int(sh.recvline().decode())
sh.recvuntil(b"N = ")
N = int(sh.recvline().decode())
e = 65537

sh.recvuntil(b"> ")
sh.sendline(str(-ctxt).encode())
sh.recvuntil(b"ponse:\n")
ptxt = int(sh.recvline().decode())

print(long_to_bytes((-ptxt) % N))
```

Flag: `404CTF{L3s_0r4cl3s_RSA_s0n7_si_fr4g1l35}`

## Partie 2

> Bonjour agent, Suite à votre récente découverte, nous avons pu extraire beaucoup d'informations de ce serveur. Malheureusement, ce service a fermé il y a une semaine, et vient juste de réouvrir après ce qui a été vraisemblablement une mise à jour de sécurité, et il ne semble plus possible d'accéder au secret. Pourriez-vous faire quelque chose?
>
> nc challenge.404ctf.fr 30594

### Description

Même chose que l'oracle précédent, sauf que N n'est pas donné.

### Solution

Entrer `-1` permet de trouver `N-1` puisque `(-1)^d = -1 = N-1`.

On peut ensuite effectuer le même exploit.

```python
from pwn import *
from Crypto.Util.number import long_to_bytes

sh = remote("challenge.404ctf.fr", 30594)
sh.recvuntil(b"craintes:\n")
ctxt = int(sh.recvline().decode())
e = 65537

# Trouver N
sh.recvuntil(b"> ")
sh.sendline(str(-1).encode())
sh.recvuntil(b"ponse:\n")
N = int(sh.recvline().decode()) + 1

sh.recvuntil(b"> ")
sh.sendline(str(-ctxt).encode())
sh.recvuntil(b"ponse:\n")
ptxt = int(sh.recvline().decode())

print(long_to_bytes((-ptxt) % N))
```

Flag: `404CTF{L3_m0dul3_357_t0uj0ur5_7r0uv4bl3}`