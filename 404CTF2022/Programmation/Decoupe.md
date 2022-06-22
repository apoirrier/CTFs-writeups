# Découpé

> Lors d'une interpellation, nous avons réussi à récupérer un disque dur. Hélas, un mécanisme de protection fait main a détruit un document qui se trouvait dessus ! Seriez-vous capable de le reconstituer ?

## Description

On nous fournit un fichier zip. Quand on l'extrait, on obtient plein de petites images de taille 33*33.
Il va probablement falloir les assembler.

## Solution

Le code Python suivant fait l'affaire:

```python
from PIL import Image
import os
import numpy as np

image_ints = list(range(1,577))

w = 24
h = 576 // w
i = 0
j = 0
image = Image.new(mode="RGB",size=(w*33, h*33))
for d in image_ints:
    segment = Image.open("output/{}.png".format(d))
    image.paste(segment, (33*j, 33*i, 33*j+33, 33*i+33))
    j += 1
    if j == w:
        i += 1
        j = 0

image.save("reconstructed.png")
```

On obtient l'image suivante:

![reconstructed](../images/reconstructed.png)

Flag: `404CTF{M4n1PuL4T10N_d'1M4g3S_F4c1L3_n0N?}`.