# Shuffled

> Oops, nous avons mélangé les caractères du flag. Pourrez-vous les remettre dans l'ordre ?

```python
import random

flag = list(open("flag.txt", "rb").read().strip())
random.seed(random.randint(0, 256))
random.shuffle(flag)
print(bytes(flag).decode())
```

## Solution

As the seed is set, there are actually only 256 possible permutations, so we can test them all, invert them and find which one gives a flag starting with `FCSC`.

```python
import random

shuffled = list(open("output.txt", "r").read().strip())
N = len(shuffled)
flag = [""]*N
for i in range(257):
    s = list(range(N))
    random.seed(i)
    random.shuffle(s)
    for j in range(N):
        flag[s[j]] = shuffled[j]
    if flag[:4] == ["F", "C", "S", "C"]:
        print("".join(flag))
        break
```

Flag: `FCSC{d93d32485aec7dc7622f13cd93b922363911c36d2ffd4f829f4e3264d0ac6952}`