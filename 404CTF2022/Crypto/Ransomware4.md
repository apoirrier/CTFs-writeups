# Hackllebarde ransomware [4/4]

> Pendant que vous travailliez sur l'analyse forensique, nos experts en rétro-ingénierie ont pu extraire le code utilisé pour chiffrer nos documents. Hélas, pas moyen de retrouver la clé de chiffrement, elle n'a pas été sauvegardée du tout !! Le département de cryptographie est formel, les données sont bel et bien perdues. Néanmoins jetez un coup d'oeil, on ne sait jamais...

Voici le code qu'on nous fournit:

```c
/* 
 * Bonjour, agent ! 
 * Nous avons réussi à reconstituer ce code depuis le binaire du ransomware qui se trouvait sur nos machines. 
 * Hélas, la clé de chiffrement est aléatoire et le département crypto dit que c'est sans espoir.
 * Vous pensez pouvoir faire quelque chose ?
 * Quelques informations : le ransomware tournait sur nos machines qui possèdent une architecture AMD x86_64, avec un système d'exploitation Linux. 
 * Aussi, nous n'avons pas réussi à récupérer le seed utilisé, donc nous avons fait en sorte que vous puissiez le choisir pour expérimenter.
 * Bonne chance !
 */

#include <stdio.h>
#include <stdlib.h>
 
// Code récupéré du ransomware Hackllebarde
int main(int argc, char** argv)
{
	// Cette partie du code a été rajoutée pour remplacer le seed qui a été perdu
	if (argc != 2) {
		perror("Nombre d'arguments invalide !");
		exit(1);
	}
	// peut échouer, mettez les bons arguments !
	int seed = strtol(argv[1], NULL, 10);
	// à partir de ce point, tout le code est celui récupéré et reconstitué du ransomware.
	// (excepté les commentaires)
	char array[8];
 	initstate(seed, array, 27);
	FILE* file = fopen("./flag.pdf", "rb");
	FILE* encryptedfile = fopen("./flag.pdf.enc", "wb");
	if (file == NULL || encryptedfile == NULL) {
		perror("Files cannot be opened ! Hackllebarde ransomware have failed :-(");
		exit(1);
	}
	int key, len;
	char data[4];
	char* keychar;
	while ((len = fread(&data, sizeof(char), 4, file)) == 4) {
		// on ne peut rien faire contre une clé 100% aléatoire !!!
		key = rand();
		keychar = (char*)&key;
		for(int i=0; i<len; i++) {
			data[i] ^= keychar[i];
		}
		fwrite(&data, sizeof(char), 4, encryptedfile);
	}
	fclose(file);
	fclose(encryptedfile);
	puts("Hackllebarde ransomware is a success ! :-D");
	return(0);
}	
```

## Description

Le fichier est un réel ransomware: il encrypte le fichier `flag.txt`.

A nous de le décrypter.

Heureusement pour nous, la clé de chiffrement est générée à partir de `rand`, qui n'est pas un réel générateur aléatoire mais qui est pseudo-aléatoire.

Ainsi, connaître la graine (seed) qui a été utilisée nous permet de décoder l'intégralité du fichier.

Par ailleurs, nous savons que le fichier PDF clair commence probablement par `%PDF`, donc cela nous permet de connaître la première clé utilisée.

## Comment fonctionne le générateur

Le générateur est initialisé avec `initstate(seed, array, 27);`. Ne connaissant pas la fonction, je suis allé regarder [les sources](https://github.com/bminor/glibc/blob/master/stdlib/random_r.c).

> Initialize the state information in the given array of N bytes for future random number generation.  Based on the number of bytes we are given, and the break values for the different R.N.G.'s, we choose the best (largest) one we can and set things up for it.

Ici, la valeur donnée est 27. Or, les break values sont 8, 32, 64, 128, 256.
Cela signifie donc qu'on a un générateur de type `TYPE_0`.

On trouve dans le même fichier la fonction `rand`:

```c
if (buf->rand_type == TYPE_0)
{
    int32_t val = ((state[0] * 1103515245U) + 12345U) & 0x7fffffff;
    state[0] = val;
    *result = val;
}
```

Pour `TYPE_0`, il s'agit donc d'un simple générateur congruentiel linéaire. On peut donc retrouver la suite.

## Solution

Je pensais avoir besoin de faire un brute force pour avoir l'intégralité du state (puisqu'on utilise que 4 bytes), mais en fait le state fait 4 bytes.

Donc l'exploit est immédiat:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

with open("flag.pdf.enc", "rb") as f:
    encrypted = f.read()

# Copie en Python du LCG
def rand(state):
    return (1103515245*state + 12345) & 0x7fffffff

# Décrypte une fois le state trouvé
def decrypt(state):
    with open("flag_dec.pdf", "wb") as f:
        for i in range(0,len(encrypted),4):
            key = long_to_bytes(state).rjust(4, b'\x00')
            for j in range(4):
                f.write(bytes([encrypted[i+j] ^ key[3-j]]))
            state = rand(state)

# Calcul du state initial:
ptxt = b"%PDF"
key = [0] * 4
for j in range(4):
    key[3-j] = encrypted[j] ^ ptxt[j]
key = bytes_to_long(bytes(key))

decrypt(key)
```

Flag: `404CTF{Wow_p4s_Tr3S_r4nD0m_T0ut_c4}`