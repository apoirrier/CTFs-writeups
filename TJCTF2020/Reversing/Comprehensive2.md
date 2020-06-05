# Comprehensive 2

> His power level increased... What do I do now??
> 
> Output: [1, 18, 21, 18, 73, 20, 65, 8, 8, 4, 24, 24, 9, 18, 29, 21, 3, 21, 14, 6, 18, 83, 2, 26, 86, 83, 5, 20, 27, 28, 85, 67, 5, 17, 2, 7, 12, 11, 17, 0, 2, 20, 12, 26, 26, 30, 15, 44, 15, 31, 0, 12, 46, 8, 28, 23, 0, 11, 3, 25, 14, 0, 65]

Attached is the following Python file:

```python
m = '[?????]'
n = '[?????]'

a = 'abcdefghijklmnopqrstuvwxyz'
p = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

assert len(m) == 63 and set(m).issubset(set(a + p))
assert len(n) == 7  and set(n).issubset(set(a))
assert m.count('tjctf{') == 1 and m.count('}') == 1 and m.count(' ') == 5

print(str([x for z in [[[ord(m[i]) ^ ord(n[j // 3]) ^ ord(n[i - j - k]) ^ ord(n[k // 21]) for i in range(j + k, j + k + 3)] for j in range (0, 21, 3)] for k in range(0, len(m), 21)] for y in z for x in y])[1:-1])
```

## Description

Here we have an encrypted message `m` using a key `n`. We know the message is 63 characters long using lowercase letters and symbols. It holds the flag (`tjctf{` and `}` appear only once), and there are 5 spaces in the message.

On the other hand, the key is only lowercase characters and has 7 characters.

Let's have a closer look at the encryption.

We have a definition of a 3D array, then it is flattened. The code above is equivalent to:

```python
big_array = [[[ord(m[i]) ^ ord(n[j // 3]) ^ ord(n[i - j - k]) ^ ord(n[k // 21]) for i in range(j + k, j + k + 3)] for j in range (0, 21, 3)] for k in range(0, len(m), 21)]
print(str([x for z in big_array for y in z for x in y])[1:-1])
```

Let's now reverse how the array is constructed. In each cell of the final array, a xor between 4 values happen. The following explains the indexes that are xored together:

| Final index | 0 | 1 | 2 | 3 | 4 | 5 | 6 |...|20 |21 |...|
|:-----------:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| m[i]        | 0 | 1 | 2 | 3 | 4 | 5 | 6 |...|20 |21 |...|
| n[j // 3]   | 0 | 0 | 0 | 1 | 1 | 1 | 2 |...| 6 | 0 |...|
| n[i - j - k]| 0 | 1 | 2 | 0 | 1 | 2 | 0 |...| 2 | 0 |...|
| n[ k // 21] | 0 | 0 | 0 | 0 | 0 | 0 | 0 |...| 0 | 1 |...|

## Solution

We know that `tjctf{` appears somewhere in the input. Knowing this, we can bruteforce its position. If we assume it appears at index `i`, then this gives us some constraints on the characters appearing in the password. 

First some constraints may be incompatible, meaning that given the constraints, `tjctf{` cannot appear. The following function checks this.

It takes as input `begin` the expected beginning index of `tjctf{`, and an array `n` representing the password (all values are -1 of not defined).

Remember the output is computed as `output[i] = input[i] ^ n[x1] ^ n[x2] ^ n[x3]`. Therefore there are two possibilities:
- two of the `xi` are equals, and in this case the remaining value `n[xj]` is determined by the input and the output
- otherwise no additional constraint, except if two other `n[xi]` are known.

```python
big_one = [[[j//3 for i in range(j + k, j + k + 3)] for j in range (0, 21, 3)] for k in range(0, 63, 21)]
coord1 = [x for z in big_one for y in z for x in y]
big_one = [[[i - j - k for i in range(j + k, j + k + 3)] for j in range (0, 21, 3)] for k in range(0, 63, 21)]
coord2 = [x for z in big_one for y in z for x in y]
big_one = [[[k // 21 for i in range(j + k, j + k + 3)] for j in range (0, 21, 3)] for k in range(0, 63, 21)]
coord3 = [x for z in big_one for y in z for x in y]

def verify(begin, n):
    for i in range(begin, begin+6):
        # Determine which case we are in
        free_coord = -1
        if coord1[i] == coord2[i]:
            free_coord = coord3[i]
        if coord3[i] == coord2[i]:
            free_coord = coord1[i]
        if coord1[i] == coord3[i]:
            free_coord = coord2[i]
        
        if free_coord == -1:
            # Case 2
            if (n[coord1[i]] == -1) + (n[coord2[i]] == -1) + (n[coord3[i]] == -1) == 0:
                # We know all 3 coords
                if n[coord1[i]] ^ n[coord2[i]] ^ n[coord3[i]] != ord(known[i-begin]) ^ output[i]:
                    return False
            if (n[coord1[i]] == -1) + (n[coord2[i]] == -1) + (n[coord3[i]] == -1) == 1:
                # We know 2 of them
                if n[coord1[i]] == -1:
                    n[coord1[i]] = ord(known[i-begin]) ^ output[i] ^ n[coord2[i]] ^ n[coord3[i]]
                if n[coord2[i]] == -1:
                    n[coord2[i]] = ord(known[i-begin]) ^ output[i] ^ n[coord1[i]] ^ n[coord3[i]]
                if n[coord3[i]] == -1:
                    n[coord3[i]] = ord(known[i-begin]) ^ output[i] ^ n[coord1[i]] ^ n[coord2[i]]
            continue
        # This is case 1
        if n[free_coord] == -1:
            # The remaining coord is still free
            n[free_coord] = ord(known[i-begin]) ^ output[i]   
        else:
            if n[free_coord] != ord(known[i-begin]) ^ output[i]:
                return False
    # Finally, check all characters in n are alphabetic lowercase
    for c in n:
        if c != -1 and chr(c) not in a:
            return False
    return True
```

Once we know if some position is valid or not, and we have some constraints on the password, we can bruteforce the remaining characters in the password.

```python
# Helper function, returns first index of unknown char in password
def find_1(n):
    for i in range(len(n)):
        if n[i] == -1:
            return i
    return -1

def brute_force(begin, original_n):
    i = find_1(original_n)
    if i == -1:
        # password is full
        m = decrypt(original_n)
        if m.count(ord('}')) == 1 and m.count(ord(' ')) == 5:
            # We verify if constraints are ok
            print("Seems ok for position ", begin)
            print(original_n)
            print("".join([chr(c) for c in m]))
        return
    # else we do not know char i in password, let's bruteforce it.
    for z in a:
        n = [c for c in original_n]
        n[i] = ord(z)
        if verify(begin, n):
            brute_force(begin, n)
```

Finally we can find the flag by bruteforcing on start position:

```python
known = "tjctf{"
for begin in range(56):
    n = [-1]*7
    if verify(begin, n):
        original_n = [c for c in n]
        brute_force(begin, original_n)
# hata o sagashiteimasu ka? dozo, tjctf{sumimasen_flag_kudasaii}.
```

Flag: `tjctf{sumimasen_flag_kudasaii}`