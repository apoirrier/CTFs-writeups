# L'énigme de la Crypte

> Une livraison de souffre doit avoir lieu 47°N 34 2°W 1 39.
> 
> Elle sera effectuée par un certain REJEWSKI. Il a reçu des instructions sur un foulard pour signaler à Evil Gouv son arrivée imminente.
> 
> Nous avons une photo du foulard, mais celle-ci n'est pas très nette et nous n'avons pas pu lire toutes les informations. Le fichier foulard.txt, est la retranscription du foulard.
> 
> Nous avons un peu avancé sur les parties illisibles :
>
> (texte illisible 1) est deux lettres un espace deux lettres. Il pourrait y avoir un lien avec le dernier code d'accès que vous avez envoyé à Antoine Rossignol.
> 
> (texte illisible 2) a été totalement effacé et enfin (texte illisible 3) semble être deux lettres.
> 
> REJEWSKI vient d'envoyer un message (final.txt). Il faut que vous arriviez à le déchiffrer. Je vous conseille d'utiliser openssl pour RSA.
> 
> Le flag est de la forme DGSESIEE{MESSAGE} où MESSAGE correspond à la partie centrale du texte en majuscules sans espace.

Le fichier `final.txt` contient de la data.

Le fichier `foulard.txt` contient le texte suivant:

> Mission Scherbius
>
> Chiffrez un message suivi de votre nom avec la machine de type M3 avec cette disposition :
>
> Uniquement les impairs en ordre croissant
>
> Ringstellung : REJ
>
> Steckerverbindungen : (texte illisible 1)
>
> Grundstellung : MER
>
> (texte illisible 2): B(texte illisible 3)
>
>Le rÃ©sultat (texte) doit Ãªtre ensuite chiffrÃ© avec RSA en utilisant notre clÃ© publique avant de nous l'envoyer. Je vous rappelle notre clÃ© publique :
>
>Modulus (dÃ©cimal):
>
> 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216870038352484922422622979684865170307405907272815653581732377164114195025335694039872221524699156538352092782201392513118326772302632498764753996118057437198905106508696675497143847180616766425109043955104189270381382844602871223783458512671511503420521749067165952916834014926827585314522687939452292676577212513301
>
> PublicExponent (dÃ©cimal) : 65537

On a donc un texte chiffré par la méthode décrite sur le foulard. Il y a une première encryption sur une machine M3, qui décrit une machine Enigma. Les réglages sont décrits en partie.

La seconde partie encrypte le ciphertext Enigma avec RSA.

## Casser RSA

Heureusement pour nous, il est facile de casser l'encryption RSA en factorisant le modulus. J'utilise [factordb](http://factordb.com/index.php) pour factoriser le modulus. 

Le ciphertext Enigma est `IVQDQT NHABMPSVBYYUCJIYMJBRDWXAXP  THYVCROD`.

Reste à régler la machine. La [page Wikipedia](https://fr.wikipedia.org/wiki/Enigma_(machine)#Pr%C3%A9paration_de_la_machine) explique très bien les réglages:

> Chaque mois de l'année, dans chaque réseau, de nouvelles instructions de mise en œuvre spécifient des modifications (quotidiennes ou plus fréquentes) de plusieurs réglages. Les réglages internes sont les trois premiers pas de la procédure :
>
> 1. Ordre des rotors (Walzenlage) : choix et positionnement des trois rotors prescrits par les instructions (ex : I-V-III).
> 2. Disposition de la bague (Ringstellung) des rotors gauche, milieu et droit (ex : 06-20-24 affichés FTX) prescrite par les instructions.
> 3. Permutations des fiches du tableau de connexions (Steckerverbindungen) (ex : UA PF, etc.) prescrites par les instructions. Un des chiffreurs dispose la machine en conséquence. La procédure continue avec les réglages externes.
> 4. Le premier chiffreur dispose les trois rotors sur la position initiale (Grundstellung) définie par les instructions quotidiennes, ex : JCM (c'est la source du « Herivel Tip » qui réduit les spéculations des cryptanalystes à quelques dizaines de combinaisons).
> 5. Le premier chiffreur choisit au hasard un réglage initial de rotors et le frappe deux fois, ex : BGZBGZ. C'est la clef brute du message (et la source des fameuses « cillies »).
> 6. Le second chiffreur note le résultat affiché par les voyants ; c'est l'indicateur ou clef chiffrée (ex. : TNUFDQ).
> 7. Le premier chiffreur dispose ses rotors sur BGZ puis entre au clavier le texte du message en clair, lettre par lettre ; le second chiffreur note les lettres signalées par l'allumage des voyants.

La description nous donne l'ordre des rotors: I III V (impairs en ordre croissant).

La Ringstellung est donnée.

Les permutations Steckerverbindungen sont trouvées grâce au message donné à Antoine Rossignol (voir [writeup correspondant](crypto.md)). Le message est `b a:e z`, donc on hésite entre les Steckerverbindungen `BA EZ` ou `BE AZ`.

Grundstellung est également donné par le foulard.

Enfin, le texte illisible 2 est probablement la clef brute du message. On sait donc qu'elle commence par B, et doit donner le chiffrage `IVQDQT`.

On utilise le module Enigma de [CyberChef](https://gchq.github.io/CyberChef/) pour résoudre le challenge.

En entrant B comme première lettre à chiffrer et les réglages ci-dessus, comme on sait que la première lettre est I, on en déduit que les Steckerverbindungen sont `BE AZ` en testant les deux possibilités.

Ensuite on bruteforce les lettres de la clé pour obtenir la clé initiale. Afin d'automatiser le processus, j'ai utilisé la librairie [py-enigma](https://pypi.org/project/py-enigma/) et le code Python suivant:

```python
from enigma.machine import EnigmaMachine

def test(key):
    machine = EnigmaMachine.from_key_sheet(
        rotors='I III V',
        reflector='B',
        ring_settings='R E J',
        plugboard_settings="BE AZ"
    )
    machine.set_display('MER')
    ctxt = machine.process_text(key + key)
    
    if ctxt == "IVQDQT":
        print(key)
        exit()

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

for a in alphabet:
    for b in alphabet:
        test("B{}{}".format(a,b))
```

J'obtiens la clé `BFG`.

En entrant cette clé dans CyberChef et le reste du ciphertext, j'obtiens le flag. A noter que le nom de l'opérateur d'obtient si on chiffre directement la dernière partie du ciphertext avec la clé.

Flag: `LESSANGLOTSLONGSDESVIOLONS`