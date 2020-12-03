# Le Discret Napier

> Stockos a encore choisi un code d'accès qui est solution d'une énigme mathématique ! Retrouvez x tel que : 17^x ≡ 183512102249711162422426526694763570228 [207419578609033051199924683129295125643]
>
> Le flag est de la forme : DGSESIEE{x} avec x la solution 

Un problème classique où on nous demande de résoudre une équation à priori impossible en un temps raisonnable, un logarithme discret sur un Z/pZ.

## Comment casser un logarithme discret ?

On fait chauffer [SageMath](https://www.sagemath.org/fr/) pour disposer des constructions classiques de théorie des nombres.

```python
N = 207419578609033051199924683129295125643
Z = Integers(N) # Le corps Z/NZ

a = C(183512102249711162422426526694763570228)
b = C(17)
```

On remarque rapidement quelque chose d'intéressant : en regardant l'ordre de Z/NZ, on voit qu'il est factorisable en de nombreux petits facteurs.

```python
print(factor(N-1)) # N est premier, donc l'ordre de Z/NZ est N-1.
```
> 2 * 43 * 47 * 373 * 2707 * 2608763 * 19481470025232063548957

Si vous n'êtes pas familiers avec la crypto, vous vous demandez peut-être pourquoi c'est intéressant ?

## Le problème des sous-groupes dans Z/pZ

C'est un problème qui est décrit notamment dans [ce très bon papier](https://dl.acm.org/doi/10.1145/2810103.2813707) (#3.5. Attacks on composite-order subgroups).

L'idée est la suivante. On note `q` l'ordre de `b` à factoriser. Si `q` est factorisable en de nombreux petits facteurs, on peut résoudre le logarithme pour chacun des sous-groupes d'ordre les facteurs de `q`.

Concrèment, l'algorithme suivant permet de résoudre le logarithme :

```python
q = Z(b).multiplicative_order()
g = b # b est par définition le générateur du sous-groupe de son ordre.
xps = []
ps = []
for p in factor(q): # p est de la forme (facteur, exposant)
    print(p)
    ap = a ^ (q / p[0]) # La valeur de a dans le sous-groupe d'ordre p[0]
    gp = g ^ (q / p[0]) # Un générateur du sous-groupe d'ordre p[0]
    xp = ap.log(gp) # Sage peut résoudre parce que l'ordre de gp est petit, contrairement à l'ordre de g qui lui est énorme.
    xps.append(xp)
    ps.append(p[0])
```

Si on récapitule, on  a `a = b ^ x`, donc `(g ^ (q / p)) ^ x_p = ap = (g ^ (q/p)) ^ x`, soit `x = x_p [p]`. Il ne reste donc qu'à utiliser le CRT pour obtenir la valeur de x :

```python
x = CRT_list(xps, ps)
print(x)
```
> 697873717765

Le flag est donc DGSESIEE{697873717765}.