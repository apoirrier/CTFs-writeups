# Définition

> Un de vos collègues a créé un petite énigme, il est un peu lourd et vous demande depuis des semaines de la résoudre, faites lui plaisir. Voici l'énigme : Quelle heure est-t-il ?
>
> Connectez-vous via nc challengecybersec.fr 6660
>
> Le flag est de la forme : DGSESIEE{x} avec x un hash

Le tout est de deviner le format de l'heure, finalement donner la sortie de `time` marche.

Le script Python suivant affiche le flag.

```python
from pwn import *
import time

sh = remote("challengecybersec.fr", 6660)

sh.recvuntil("> ")
sh.sendline(str(int(time.time())))
print(sh.recvline())
```

Flag: `DGSESIEE{cb3b3481e492ccc4db7374274d23c659}`