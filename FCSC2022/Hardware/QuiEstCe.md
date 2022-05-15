# Qui est-ce ?

> On vous donne le circuit logique en pièce jointe, et on vous demande de donner une entrée sous forme décimale correspondante à la sortie y = 8549048879922979409, avec yi les bits de y où y62 est le MSB et y0 le LSB : (y62, ..., y0) = (1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1).
>
> Encadrez votre réponse entre FCSC{} pour obtenir le flag.
>
> Exemple : si on avait donné y = 1333333333333333337, alors le flag aurait été FCSC{6497282320360345885}.

<object data="../images/quiestce.pdf" type="application/pdf" width="700px" height="700px">
    <embed src="../images/quiestce.pdf">
        <p>This browser does not support PDFs. Please download the PDF to view it: <a href="../images/quiestce.pdf">Download PDF</a>.</p>
    </embed>
</object>

## Analysis

By analysing the circuit, we can see that there is a induction relation:
```
x[i] = y[i] ^ (x[i-2] & (1 - x[i-1]))
```

## Solution

I solved the system of equations by bruteforcing the first 2 bits, then computing the rest with the induction relation and verifying if it holds for the first 2 bits.

```python
y = 8549048879922979409
y = [(y & (1 << i)) >> i for i in range(63)]

def convert(x):
    ret = 0
    for i in range(63):
        ret += (x[i] << i)
    return ret

def trying(start):
    x = [0] * 63
    x[0], x[1] = start&1,(start&3)>>1
    for i in range(2,63):
        x[i] = y[i] ^ (x[i-2] & (1 - x[i-1]))

    if (y[0] == x[0] ^ (x[61] & (1 - x[62]))) and (y[1] == x[1] ^ (x[62] & (1 - x[0]))):
        return x
    return None

for i in range(4):
    x = trying(i)
    if x is not None:
        break
print(convert(x))
```

Flag: `FCSC{7364529468137835333}`