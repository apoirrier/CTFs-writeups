# Renversons la tour!

Ce challenge est composé de deux parties indépendantes mais sur le même thème.

## Partie 1

> Nos experts ont réussi à mettre la main sur un algorithme d'authentification ultra secret utilisé par notre ennemi !
>
> Un unique mot de passe est accepté mais nous n'avons pas pu le recupérer. Pouvez-vous nous aider ?

### Description

On nous donne le code Python suivant:

```python
def tour1(password):
    string = str("".join( "".join(password[::-1])[::-1])[::-1])
    return [ord(c) for c in string]


def tour2(password):
    new = []
    i = 0
    while password != []:
        new.append(password[password.index(password[i])])
        new.append(password[password.index(password[i])] + password[password.index(password[ i + 1 %len(password)])])
        password.pop(password.index(password[i]))
        i += int('qkdj', base=27) - int('QKDJ', base=31) + 267500
    return new

def tour3(password):
    mdp =['l', 'x', 'i', 'b', 'i', 'i', 'q', 'u', 'd', 'v', 'a', 'v', 'b', 'n', 'l', 'v', 'v', 'l', 'g', 'z', 'q', 'g', 'i', 'u', 'd', 'u', 'd', 'j', 'o', 'r', 'y', 'r', 'u', 'a']
    for i in range(len(password)):
        mdp[i], mdp[len(password) - i -1 ] = chr(password[len(password) - i -1 ] + i % 4),  chr(password[i] + i % 4)
    return "".join(mdp)




mdp = input("Mot de passe : ")

if tour3(tour2(tour1(mdp))) == "¡P6¨sÉU1T0d¸VÊvçu©6RÈx¨4xFw5":
    print("Bravo ! Le flag est 404CTF{" + mdp + "}")
else :
    print("Désolé, le mot-de-passe n'est pas correct")
```

Notre mot de passe passe par trois fonctions, et une comparaison est effectuée avec une chaîne constante.

Il faut donc inverser chaque fonction.

### Solution

On remarque que pour `tour3`, les valeurs initiales de `mdp` ne sont en fait pas utilisées, et qu'il s'agit de simples assignements. On peut donc inverser la fonction en inversant chaque opération d'assignement:

```python
def invert3(mdp):
    password = [0] * len(mdp)
    for i in range(len(mdp)):
        password[i], password[len(password)-i-1] =  ord(mdp[len(password) - i -1 ]) - i%4, ord(mdp[i]) - i%4
    return password
```

Pour `tour2`, l'entrée est `password` et la sortie `new`. On remarque que `int('qkdj', base=27) - int('QKDJ', base=31) + 267500` vaut en fait 0: ainsi, à chaque tour de boucle, `i` vaut toujours 0, `password.index(password[i])` vaut également 0, et le premier élément de password est ajouté à `new` ainsi qu'un autre caractère, et on enlève le premier caractère de `password`.

Ainsi, les caractères pairs de `new` sont exactement ceux de `password`, et on a la fonction inverse très simple:

```python
def invert2(new):
    return new[::2]
```

Quant à `tour1`, il s'agit de convertir chaque caractère par son entier ASCII, et d'inverser l'ordre de la liste. On inverse donc la fonction ainsi:

```python
def invert1(s):
    return "".join([chr(x) for x in s[::-1]])
```

Et on trouve le flag:

```python
mdp = "¡P6¨sÉU1T0d¸VÊvçu©6RÈx¨4xFw5"
mdp = invert1(invert2(invert3(mdp)))
print(f"404CTF{mdp}")
```

Flag: `404CTF{P4sS1R0bUst3Qu3C4}`.

## Partie 2

> Nos experts ont eu vent d'un tout nouvel algorithme d'authentification qui donne du fil à retordre à nos agents ! Certains disent que réussir à le craquer pourrait inverser le cours des choses.
>
> Attention, nous ne sommes pas sûr que ce fichier soit exactement ce qu'il semble être.

On nous donne un fichier `.asm`, mais comme l'indique l'énoncé, il ne s'agit pas d'un fichier ASM. On effectue `file reverse2.asm` et on se rend compte qu'il s'agit en fait d'un fichier ASCII. En le lisant, on voit que c'est du python bytecode.

De ce que je comprends, le python bytecode utilise 2 stacks: une pour la donnée et une pour les fonctions.

Je vais donc inverser partie par partie.

### Ligne 3

```
0 LOAD_GLOBAL              0 (input)
2 CALL_FUNCTION            0
4 STORE_FAST               0 (inp)
```

Pas de difficulté ici, on charge la fonction puis on l'appelle et on met le résultat dans une variable.
Ce bout de code correspond à `inp = input()`

### Lignes 5 à 8

```
6 LOAD_CONST               1 (True)
8 STORE_FAST               1 (s)

10 LOAD_CONST               2 ('')
12 STORE_FAST               2 (n)

14 LOAD_CONST               2 ('')
16 STORE_FAST               3 (p)

18 BUILD_LIST               0
20 LOAD_CONST               3 ((88, 1, 140, 1, 203, 208, 89, 207, 132, 191, 178, 110, 138, 132, 210, 1, 140, 156, 138, 140, 191, 187, 89, 89, 187, 1, 208, 231, 161, 235, 178, 188, 187, 132, 187))
22 LIST_EXTEND              1
24 STORE_FAST               4 (f)
```

Ici on charge des constantes et on les assigne à des variables, la dernière étant une liste.

```python
s = True
n = ''
p = ''
f = [88, 1, 140, 1, 203, 208, 89, 207, 132, 191, 178, 110, 138, 132, 210, 1, 140, 156, 138, 140, 191, 187, 89, 89, 187, 1, 208, 231, 161, 235, 178, 188, 187, 132, 187]
```

### Lignes 10 à 12

```
26 LOAD_FAST                0 (inp)
28 LOAD_CONST               2 ('')
30 COMPARE_OP               2 (==)
32 POP_JUMP_IF_FALSE       46

34 LOAD_GLOBAL              1 (print)
36 LOAD_CONST               4 ('Nope')
38 CALL_FUNCTION            1
40 POP_TOP

42 LOAD_FAST                1 (s)
44 RETURN_VALUE
```

On a un d'abord un branchement, s'il est vrai les instructions 34 à 44 sont effectuées, sinon on continue le programme.
Le code correspondant est:

```python
if inp == '':
    print('Nope')
    return 1
```

### Lignes 14 et 15

```
>>  46 LOAD_GLOBAL              2 (range)
    48 LOAD_GLOBAL              3 (len)
    50 LOAD_FAST                0 (inp)
    52 CALL_FUNCTION            1
    54 CALL_FUNCTION            1
    56 GET_ITER
>>  58 FOR_ITER                32 (to 92)
    60 STORE_FAST               5 (k)

    62 LOAD_FAST                2 (n)
    64 LOAD_FAST                0 (inp)
    66 LOAD_GLOBAL              4 (int)
    68 LOAD_GLOBAL              3 (len)
    70 LOAD_FAST                0 (inp)
    72 CALL_FUNCTION            1
    74 LOAD_FAST                5 (k)
    76 BINARY_SUBTRACT
    78 LOAD_CONST               5 (1)
    80 BINARY_SUBTRACT
    82 CALL_FUNCTION            1
    84 BINARY_SUBSCR
    86 INPLACE_ADD
    88 STORE_FAST               2 (n)
    90 JUMP_ABSOLUTE           58
```

On commence à avoir des instructions un peu plus complexes.

Les instructions 46 à 54 sont de simples appels de fonction qui donnent `range(len(inp))`, et on le donne comme itérateur pour la boucle for (et le `(to 92)` signifie que lorsque la boucle est terminée, on passe à l'instruction 92).

On a ensuite la boucle for, dont la variable d'itération est `k`. On peut regarder l'état des deux stacks à chaque instruction:

| instruction | STACK | FUNCTIONS |
|-------------|------|--------|
| LOAD_FAST n | n | |
| LOAD_FAST inp | n, inp | |
| LOAD_GLOBAL int | n, inp | int |
| LOAD_GLOBAL len | n, inp | int, len |
| LOAD_FAST inp | n, inp, inp | int, len |
| CALL_FUNCTION | n, inp, len(inp) | int |
| LOAD_FAST k | n, inp, len(inp), k | int |
| BINARY_SUBSTRACT | n, inp, len(inp) - k | int |
| LOAD_CONST 1 | n, inp, len(inp) - k, 1 | int |
| BINARY_SUBSTRACT | n, inp, len(inp) - k - 1 | int |
| CALL_FUNCTION | n, inp, int(len(inp) - k - 1) | |
| BINARY_SUBSCR | n, inp[int(len(inp) - k - 1)] | |
| INPLACE_ADD | n + inp[int(len(inp) - k - 1)] | |

So basically the code is equivalent to:

```python
for k in range(len(inp)):
    n += inp[len(inp) - k - 1]
```

### Ligne 17

```
>>  92 BUILD_LIST               0
    94 LOAD_CONST               6 ((159, 44, 176, 145, 103, 133, 49, 97, 113, 136, 184, 60, 85, 69, 64, 186, 182, 37, 56, 170, 19, 108, 152, 183, 41, 197, 252, 77, 35, 127, 198, 43, 148, 48, 46, 62, 15, 139, 95, 9, 38, 73, 160, 175, 226, 254, 129, 211, 132, 7, 90, 208, 187, 164, 158, 201, 116, 93, 54, 87, 126, 128, 16, 50, 244, 12, 4, 188, 166, 59, 235, 28, 199, 92, 216, 192, 231, 51, 61, 39, 220, 180, 204, 210, 178, 75, 17, 91, 143, 94, 34, 70, 222, 125, 131, 195, 33, 223, 242, 156, 232, 140, 67, 24, 111, 141, 162, 66, 45, 207, 138, 202, 89, 122, 191, 1, 110, 203, 241, 196, 82, 72, 76, 161, 117, 88, 105, 147, 119, 6, 157, 249, 168, 81, 32, 224, 237, 5, 146, 27, 80, 57, 42, 102, 172, 219, 114, 8, 31, 26, 238, 30, 212, 106, 221, 240, 118, 149, 165, 65, 83, 154, 151, 96, 36, 253, 250, 100, 74, 21, 189, 169, 239, 142, 173, 217, 181, 86, 29, 68, 155, 115, 225, 135, 0, 130, 101, 112, 206, 185, 227, 245, 18, 58, 243, 137, 20, 99, 3, 2, 233, 22, 55, 11, 13, 214, 84, 200, 47, 190, 205, 209, 53, 194, 229, 171, 248, 230, 109, 234, 236, 98, 213, 247, 150, 104, 79, 134, 71, 144, 25, 218, 107, 179, 124, 167, 251, 14, 78, 193, 40, 163, 123, 10, 246, 120, 23, 174, 63, 153, 228, 52, 121, 177, 215))
    96 LIST_EXTEND              1
    98 STORE_FAST               6 (d)
```

sets `d` to the given list.

### Lignes 19 et 20

```
    100 LOAD_GLOBAL              2 (range)
    102 LOAD_GLOBAL              3 (len)
    104 LOAD_FAST                0 (inp)
    106 CALL_FUNCTION            1
    108 CALL_FUNCTION            1
    110 GET_ITER
>>  112 FOR_ITER                32 (to 146)
    114 STORE_FAST               7 (i)

    116 LOAD_FAST                3 (p)
    118 LOAD_GLOBAL              5 (chr)
    120 LOAD_FAST                6 (d)
    122 LOAD_GLOBAL              4 (int)
    124 LOAD_GLOBAL              6 (ord)
    126 LOAD_FAST                2 (n)
    128 LOAD_FAST                7 (i)
    130 BINARY_SUBSCR
    132 CALL_FUNCTION            1
    134 CALL_FUNCTION            1
    136 BINARY_SUBSCR
    138 CALL_FUNCTION            1
    140 INPLACE_ADD
    142 STORE_FAST               3 (p)
    144 JUMP_ABSOLUTE          112
```

Encore une boucle for, et on peut à nouveau effectuer une analyse des stacks pour savoir ce qui se passe à chaque tour de boucle:

| instruction | STACK | FUNCTIONS |
|-------------|------|--------|
| LOAD_FAST p | p | |
| LOAD_GLOBAL chr | p | chr |
| LOAD_FAST d | p, d | chr |
| LOAD_GLOBAL int | p, d | chr, int |
| LOAD_GLOBAL ord | p, d | chr, int, ord |
| LOAD_FAST n | p, d, n | chr, int, ord |
| LOAD_FAST i | p, d, n, i | chr, int, ord |
| BINARY_SUBSCR | p, d, n[i] | chr, int, ord |
| CALL_FUNCTION | p, d, ord(n[i]) | chr, int |
| CALL_FUNCTION | p, d, int(ord(n[i])) | chr |
| BINARY_SUBSCR | p, d[int(ord(n[i]))] | chr |
| CALL_FUNCTION | p, chr(d[int(ord(n[i]))]) | |
| INPLACE_ADD | p + chr(d[int(ord(n[i]))]) | |

Le code équivalent est donc:

```python
for i in range(len(inp)):
    p += chr(d[ord(n[i])])
```

### Lignes 22 à 26

```
>>  146 LOAD_GLOBAL              2 (range)
    148 LOAD_GLOBAL              3 (len)
    150 LOAD_FAST                4 (f)
    152 CALL_FUNCTION            1
    154 CALL_FUNCTION            1
    156 GET_ITER
>>  158 FOR_ITER                40 (to 200)
    160 STORE_FAST               8 (j)

    162 LOAD_FAST                4 (f)
    164 LOAD_FAST                8 (j)
    166 BINARY_SUBSCR
    168 LOAD_GLOBAL              6 (ord)
    170 LOAD_FAST                3 (p)
    172 LOAD_FAST                8 (j)
    174 BINARY_SUBSCR
    176 CALL_FUNCTION            1
    178 COMPARE_OP               3 (!=)
    180 POP_JUMP_IF_FALSE      158

    182 LOAD_GLOBAL              1 (print)
    184 LOAD_CONST               7 ('Nope !')
    186 CALL_FUNCTION            1
    188 POP_TOP

    190 LOAD_FAST                1 (s)
    192 ROT_TWO
    194 POP_TOP
    196 RETURN_VALUE
    198 JUMP_ABSOLUTE          158

>>  200 LOAD_FAST                1 (s)
    202 RETURN_VALUE
```

On a de nouveau une boucle for à analyser:

| instruction | STACK | FUNCTIONS |
|-------------|------|--------|
| LOAD_FAST f | f | |
| LOAD_FAST j | f, j | |
| BINARY_SUBSCR | f[j] | |
| LOAD_GLOBAL ord | f[j] | ord |
| LOAD_FAST p | f[j], p | ord |
| LOAD_FAST j | f[j], p, j | ord |
| BINARY_SUBSCR | f[j], p[j] | ord |
| CALL_FUNCTION | f[j], ord(p[j]) | |

So the for loop is comparing if `f[j] != ord(p[j])` and if that is the case, it prints "Nope" and exits.

### Final analysis

So we have enough to get the flag: the program performs the operation:

```python
for k in range(len(inp)):
    n += inp[int(len(inp) - k - 1)]
for i in range(len(inp)):
    p += chr(d[int(ord[n[i]])])
```

Then it checks that p and f represent the same characters.

### Finding the flag

We can thus recover `n` such that `d[n[i]] == f[i]` for all i, and `n` is just the password reversed.

```python
n = []
for i in range(len(f)):
    n.append(d.index(f[i]))
print("".join([chr(x) for x in n[::-1]]))
```

Flag: `404CTF{L3s4pp4rencesS0ntTr0mp3uses}`.