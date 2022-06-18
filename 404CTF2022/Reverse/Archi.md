# Changement d'architecture [1/2]

> Hallebarde se met à voir grand, ils ont carrément créé une nouvelle architecture pour leurs programmes sensibles, "afin de diminuer le périmètre des attaques possibles", selon eux.
>
> Nous avons récupéré l'un de ces programmes sensibles avec l'intepréteur embarqué. Montrez-leur qu'utiliser une nouvelle architecture n'arrête pas les attaques.
>
> Format du flag : 404CTF{password}

## Description

On nous donne le binaire de la VM et un fichier binaire qui comprend le bytecode du programme.

Comme il y a une partie 2/2 où on doit écrire notre propre bytecode (que je n'ai pas réussie), j'avais décidé de reverse le programme à la main pour comprendre comment le bytecode marche, plutôt que d'utiliser un outil dynamique ou d'exécution symbolique.

Pour ce faire, j'ai donc reverse à la main le programme en apprenant chaque nouvelle instruction au fur et à mesure.

## La nouvelle architecture

L'architecture autorise des instructions sur 32 bits et sur 64 bits.
Les adresses sont alignées sur 32 bits. Lors du référencement d'une adresse pointant vers une instruction, si son bit de poids faible est mis à 1, alors il s'agit d'une instruction 32 bits.

Le bytecode est chargé, puis une pile de 0x1000 bytes est créée. La pile suit directement le code du programme en mémoire.

Par ailleurs, un tableau contenant 8 registres de 64 bits est créé.

Au début du programme, le mode d'exécution est de 32 bits.

### Instructions 32 bits

Une instruction 32 bits est découpée ainsi:

```
//  31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 21 20 09 08 07 06 05 04 03 02 01 00
// +-----------+-----------+-----------------------+-----------------------+-----------------------+
// |     z     |    type   |           x           |          opcode       |            y          |
// +-----------+-----------+-----------------------+-----------------------+-----------------------+
```

Ce mode d'instruction est principalement utilisé pour des opérations mathématiques. Dans ce cas, l'opération effectuée est:
- `registers[y] <- registers[z] op registers[x]` si `type == 0`
- `registers[y] <- registers[z] op x` sinon.

Plus précisément, les opérations autorisées sont:

| Opcode | Opération |
|--------|-----------|
| `0xd2` | `shr` |
| `0xad` | `add` |
| `0x5b` | `sub` |
| `0x4d` | `and` |
| `0x37` | `shl` |
| `0xb`  | `or`  |
| `0x10` | `xor` |


Il y a de plus une instruction `jmp` avec l'opcode `0xbb`:
- passage en mode 64 bit si `y == 9`, sinon saut à l'adresse `registers[y]`.

### Instructions 64 bits

```
//  65                   16 15 14 13 12 21 20 09 08 07 06 05 04 03 02 01 00
// +-----------//----------+-----------------------+-----------+-----------+
// |           x           |          opcode       |     y     |    type   |
// +----------//-----------+-----------------------+-----------+-----------+
```

De nouveau, `type` indique s'il faut prendre en compte `x` comme une constante (si `type` est non nul) ou comme `registers[x]`. Pour simplifier la présentation des opcodes, j'effectue la liste quand `type` est non nul.

| Opcode | Opération |
|--------|-----------|
| `0xca` | `call x` |
| `0xc3` | `cmp registers[y], x` |
| `0xbb` | `jmp` si `y, type = 0`, `jmp_eq` si `y, type = 0xff` |
| `0x90` | `io` (voir ci-dessous) |
| `0x8e` | `ret` |
| `0x65` | `push x` (voir ci-dessous si `type` est nul) |
| `0x17` | `mov registers[type], registers[y]` |
| `0x56` | `pop` (voir ci-dessous) |

*Note: il y a aussi un `jmp_gt` et `jmp_lt` mais ils ne sont pas utilisés.*

`io` regarde la valeur de `registers[7]` et effectue l'opération suivante:
- si `registers[7] == 0x23`, alors `registers[7] <- 0x76769c90b4b3e9bc`;
- si `registers[7] == 0x20`, effectue `puts(registers[6])`;
- si `registers[7] == 0x21`, effectue `registers[7] = getchar()`;

Dans le cas où `push` est appelé avec `type == 0`, alors `x` est considéré comme un tableau de 6 valeurs (une valeur prenant un octet), et la fonction effectue `push(registers[a])` pour `a` parcourant les `y` premières cases du tableau `x`.
Le même système est utilisé pour `pop`.

## Reverse le code

Une fois qu'on sait tout ça, il devient assez rapide de reverse le code donné en entrée, et je comprends qu'on doit rentrer 3 fois 8 caractères.

Chaque partie de 3 caractères est ensuite vérifiée différemment, principalement avec des XOR.

Flag: `404CTF{Is_Th1s_4rM_LiTe_??!!???}`