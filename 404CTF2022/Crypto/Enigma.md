# Enigma

> « La mission qui suit est d'une confidentialité absolue ! Nous avons intercepté un message envoyé par un membre de Hallebarde, et nous avons retrouvé la machine utilisée, une machine Enigma M3. Déchiffrez ce message, retrouvez le nom de leur contact, et déjouez les plans de nos ennemis ! »
>
> Au cours de vos recherches vous découvrez le concept « d'indice de coïncidence », qui vous intrigue particulièrement...
>
> > Vous avez à votre disposition deux répliques de machines Enigma M3, l'une en python, l'autre en C++.
Le flag est le nom du contact, n'oubliez pas d'ajouter 404CTF{} autour de son nom.

## Description

On nous donne comme promis une implémentation en Python et une en C++, et on nous donne un indice concernant l'indice de coïncidence.

D'abord un petit rappel sur le fonctionnement d'Enigma (en particulier la machine M3).

Enigma est une machine composée d'un clavier et d'une série de lampes.
Lorsqu'on appuie sur une touche du clavier, une série de mécanismes s'enclenche et permet d'allumer l'une des lampe, qui correspond à la lettre chiffrée.

Enigma permet donc ainsi un chiffrement polyalphabétique: les lettres sont chiffrées une par une, avec une clé différente pour chaque lettre.

Le mécanisme de la machine est composé de:
- 3 rotors (Walzen),
- un réflecteur (Umkehrwalze),
- un tableau de connections (Eintrittswalze).

Il y a le choix parmi 5 rotors (notés I, II, III, IV, V), et le mécanisme interne de chaque rotor peut avoir 26 positions (Ringstellung).

Il y a également le choix parmi 2 réflecteurs (B ou C).

![enigma_simple](https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Enigma-action-fr.svg/396px-Enigma-action-fr.svg.png)

Le tableau de connections permet d'effectuer une substitution, avant et après l'entrée et la sortie par les rotors. Pour cela, on utilise un certain nombre de câbles qui inversent deux lettres.

Le choix et l'ordre des 3 rotors et de leur configuration, du réflecteur et du plugboard définissent les réglages internes de la machine.

Une fois ces réglages internes définis (historiquement, ces réglages changeaient chaque jour), chaque message est encrypté avec une clé différente.
Cette clé consiste en la position initiale des rotors (Grundstellung).

*Note: historiquement parlant, la position initiale des rotors était en fait choisie par l'opérateur, mais était inclue dans les 6 premiers caractères du message.*

## Cryptanalyse

Grâce à [cet article](https://geekeries.org/2015/07/cryptanalyse-enigma-indice-de-coincidence/?doing_wp_cron=1654870696.1338028907775878906250#:~:text=L'indice%20de%20co%C3%AFncidence%20repr%C3%A9sente,lettres%20identiques%20dans%20un%20texte.&text=Pour%20un%20texte%20Fran%C3%A7ais%2C%20on,a%20donc%20un%20IC%20%3D%200.0746.), j'ai appris qu'on pouvait décorréler la recherche de la configuration des rotors et réflecteur avec la recherche du tableau de connections.

En effet, l'argument est que le tableau de connections n'effectue qu'une substitution des lettres, ce qui permet d'utiliser l'indice de coïncidence pour trouver la bonne configuration des rotors et réflecteur.

Par ailleurs, le code Python donné nous fournit le Ringstellung utilisé pour chaque rotor, dans le 3e membre du triplet:

```python
R1 = \
    ("I",
     'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
     ['Q'])
R2 = \
    ("II",
     'AJDKSIRUXBLHWTMCQGZNPYFVOE',
     ['E'])
R3 = \
    ("III",
     'BDFHJLCPRTXVZNYEIWGAKMUSQO',
     ['V'])
R4 = \
    ("IV",
     'ESOVPZJAYQUIRHXLNFTGKDCMWB',
     ['J'])
R5 = \
    ("V",
     'VZBRGITYUPSDNHLXAWMJQOFECK',
     ['Z'])
```

Ainsi, l'idée est de bruteforcer:
- toutes les combinaisons et ordre des rotors possibles
- les deux réflecteurs
- toutes les positions initiales possibles

Et on choisit la configuration qui a l'indice de coïncidence la plus élevée.

```python
from enigma import *
import itertools

TEXT = open("chiffre.txt").read().strip()
TEXT = TEXT[:500] # Pour accélerer le calcul, je ne prends que les 500 premiers caractères, ce qui est probablement largement suffisant pour l'indice de coïncidence
limit = 0.045 # Je ne prends que les solutions ayant un indice de coïncidence plus élevé.
N2 = float(len(TEXT) * (len(TEXT) - 1))
limit_int = int(limit*N2)

def coincidence(text):
    occurences = [0] * 26
    for c in text:
        occurences[ord(c) - ord('A')]+=1
    n = 0
    for x in occurences:
        n += x*(x-1)
    return n

# La fonction suivante décrypte le message avec les paramètres donnés en argument et retourne l'indice de coïncidence
def test_config(reflector_type, left_rotor_type, middle_rotor_type, right_rotor_type,
                left_rotor_config, middle_rotor_config, right_rotor_config,
			    left_rotor_initial, middle_rotor_initial, right_rotor_initial, plugboard):
    l_rotor = Rotor(left_rotor_type, left_rotor_config, left_rotor_initial)
    m_rotor = Rotor(middle_rotor_type, middle_rotor_config, middle_rotor_initial)
    r_rotor = Rotor(right_rotor_type, right_rotor_config, right_rotor_initial)

    ref = Reflector(reflector_type)

    plug = Plugboard(plugboard)

    e = Enigma(l_rotor, m_rotor, r_rotor, ref, plug)
    c = e.encrypt(TEXT)
    return coincidence(c)

# Test de toutes les configurations
def all_configs():
    rotors = [R1, R2, R3, R4, R5]
    reflectors = [B, C]

    for reflector in [reflectors[0]]:
        for left_rotor_type in [rotors[3]]:
            for middle_rotor_type in rotors:
                if left_rotor_type == middle_rotor_type:
                    continue
                for right_rotor_type in rotors:
                    if left_rotor_type == right_rotor_type or middle_rotor_type == right_rotor_type:
                        continue
                    print("Configuration:", left_rotor_type[0], middle_rotor_type[0], right_rotor_type[0])
                    for letters in itertools.product(alphabet, repeat=3):
                        current = test_config(reflector, left_rotor_type, middle_rotor_type, right_rotor_type,
                                              letters[0], letters[1], letters[2],
                                              left_rotor_type[2][0], middle_rotor_type[2][0], right_rotor_type[2][0], "")
                        if current > limit_int:
                            print(float(current)/N2, reflector, left_rotor_type[0], middle_rotor_type[0], right_rotor_type[0], letters)


all_configs()
```

On trouve la configuration suivante:
- réflecteur C
- rotors V, II, IV
- position initiale PAX.

## Trouver le plugboard

Finalement, pour trouver le plugboard, j'essaie toutes les combinaisons de 2 lettres, et je prends l'indice de coïncidence le plus élevé.

Cela me donne rapidement la combinaison `RV`, en revanche difficile de trouver la suivante avec cette méthode.

Cependant, j'arrive déjà à distinguer du texte français:

```
URGENTNOUSAGIZXJLSANSTROISJOURSVOTRECOSXOKQPERALOISEAUDEMALHEURRZEFEKWIRMAISJAIMECETEXTEDUHZZVYCZUOAMBABGAPIGYBMAJTCAYORCAXDRAAGVDCBSBRGASWSDNJXXZHRDREJSXYMMNNMTIRPNJQKMBNWWKIRLEDUCATIONQUOIQUERKMHKQSJEUNEILSAVAITMODERERBDADTJSIONSILNAFFECTAITRIETXPCDKOULAITPOINTTOUJOURSALBYEERISONETSAVAITRESPECTEOMEOEHBLESSEDESHOMMESONETAJFZHQQNEDEVOIRQUAVECBEAUCOBXCNLERITILNINSULTATJAMAISDHQOIORAILLERIESACESPROPOSWMJUIKESSIROMPUSSITUMULTUEJHTROBMEDISANCESTEMERAIRESRMQREZCISIONSIGNORANTESACENONNGVPINADESGROSSIERESACEABIAGZUITDEPARO
```

Un peu de guessing me donne le début:
```
URGENT NOUS AGIRONS DANS TROIS JOURS VOTRE CONTACT SERA L OISEAU DE MALHEUR ...
```

Flag: `404CTF{OISEAUDEMALHEUR}`
