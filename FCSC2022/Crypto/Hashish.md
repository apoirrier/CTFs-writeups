# Hash-ish

> Savez-vous comment fonctionne la fonction hash de Python ?
>
> nc challenges.france-cybersecurity-challenge.fr 2103

```python
#!/usr/bin/env python3.9
import os

try:
	flag = open("flag.txt", "rb").read()
	assert len(flag) == 70

	flag = tuple(os.urandom(16) + flag)

	challenge = hash(flag)
	print(f"{challenge = }")

	a = int(input(">>> "))
	b = int(input(">>> "))

	if hash((a, b)) == challenge:
		print(flag)
	else:
		print("Try harder :-)")
except:
	print("Error: please check your input")
```

## Description

The objective is to find a second preimage for the Python hash function of the form `(x,y)` where `x` and `y` are integers.

I have found a link towards the implementation of the hash function: [Hash of a tuple in Python](https://github.com/python/cpython/blob/main/Objects/tupleobject.c#L320).

Moreover, we found out that for small enough integers (especially for numbers having the size of a hash), `hash(x) = x` (except for -1).

## Solution

I'm lazy, so I just recoded the function in C, then choose randomly the first number of the tuple and compute the second, until they both have the correct size (less than 30 bits) so their hash is equal to the number itself.

Here is the code:

```c
#include<stdio.h>
#include<stdlib.h>

typedef size_t Py_uhash_t;
typedef ssize_t Py_hash_t;
#define _PyHASH_XXPRIME_1 ((Py_uhash_t)11400714785074694791ULL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)14029467366897019727ULL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)2870177450012600261ULL)
#define _PyHASH_XXROTATE(x) ((x << 31) | (x >> 33))  /* Rotate left 31 bits */
#define _PyHASH_ZZROTATE(x) ((x >> 31) | (x << 33))  /* Rotate right 31 bits */
/* Tests have shown that it's not worth to cache the hash value, see
   https://bugs.python.org/issue9685 */

#define PY1_INV 614540362697595703
#define PY2_INV 839798700976720815

Py_hash_t invert(Py_uhash_t res, Py_uhash_t r) {
    res -= 2 ^ (_PyHASH_XXPRIME_5 ^ 3527539UL);
    res *= PY1_INV;
    res = _PyHASH_ZZROTATE(res);
    res -= r * _PyHASH_XXPRIME_2;
    res *= PY1_INV;
    res = _PyHASH_ZZROTATE(res);
    res -= _PyHASH_XXPRIME_5;
    Py_uhash_t acc = _PyHASH_XXPRIME_5;
    return res * PY2_INV;
}

int main(void) {
    Py_hash_t h = -8527742988208040333;
    Py_hash_t z = (long)1 << 62;
    Py_hash_t r;;
    while(z > (long)1 << 60 || z < -(long)1 << 62) {
        r = (rand() % ((long)1 << 60));
        z = invert(h, r);
    }
    printf("(%ld,%ld)\n", z,r);
    return 0;
}
```
Flag: `FCSC{658232b18ebebc53c42dd373c6e9bc788f1fd5693cf8a45bcafbff46dae42e24}`
