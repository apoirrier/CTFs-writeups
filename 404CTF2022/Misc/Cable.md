# Par câble

> Un de nos agents a réussi à acquérir les tensions qui passaient à travers un câble de communication de Hallebarde. Pouvez-vous interpréter le signal ?

## Description

On nous donne un fichier texte qui contient des -1 et des 1.

Le code Python suivant permet d'extraire les chiffres:

```python
with open("Cable.txt", "r") as f:
    s = f.read()
data = [int(x) for x in s.strip().split(" ")]
```

Cela me permet par exemple de compter le nombre de caractères qu'on nous donne: il y en a 329, qui est un nombre premier. Je peux donc exclure le genre de codage par blocs de N caractères (type Baudot ou autre).

J'ai ensuite pensé à divers encodages tels que le Morse (en traçant le graphe du signal, mais cela ne donne rien), UART ou I²C (sachant que le code contient probablement `404CTF{`, j'ai essayé de voir s'il y avait des répétitions qui pourraient indiquer la présence de `404`. 

Je me suis rendu compte ensuite que la taille du paquet était en fait un multiple de 8 bits plus 1. Ainsi, peut être qu'au lieu de considérer la valeur des bits, on regarde s'il y a eu changement ou non ?

## Solution

J'implémente donc ma solution en Python.

```python
with open("Cable.txt", "r") as f:
    s = f.read()
data = [int(x) for x in s.strip().split(" ")]

bits = []
for i in range(1,len(data)):
    if data[i] == data[i-1]:
        bits.append('0')
    else:
        bits.append('1')
flag = [int("".join(bits[i:i+8]), 2) for i in range(0,len(bits),8)]
print(bytes(flag))
```

Flag: `404CTF{N0n3_R3tUrn_Z3r0_InV3rtEd_f0r3v3r}`.