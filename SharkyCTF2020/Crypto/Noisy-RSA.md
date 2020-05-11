# Noisy RSA 

> Something about this randomly generated noise doesn't seem right...

## Description

In this challenge the flag was encrypted with some randomly generated noise added. The goal was to retrieve the flag using number theory.
We were given the following algorithm and its output:

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from fractions import gcd
from secret import flag
from Crypto.Random import get_random_bytes

def encrypt(number):
	return pow(number,e,N)

def noisy_encrypt(a,m):
	return encrypt(pow(a,3,N)+(m << 24))

e = 3
p = getStrongPrime(512)
q = getStrongPrime(512)

while (gcd(e,(p-1)*(q-1)) != 1):
	p = getStrongPrime(512)
	q = getStrongPrime(512)

N = p * q

print("N : " + str(N) + "\n")
print("e : " + str(e) + "\n")

rand = bytes_to_long(get_random_bytes(64))

ct = []
ct.append(encrypt(rand << 24))

for car in flag:
	ct.append(noisy_encrypt(car,rand))

print(ct)
```

## Solution

### Algorithm analysis

This algorithm is a classical RSA algorithm were `e` is the public key and `N` the modulus, if we could retrieve `p`,`q` we would be able to compute `d` the private key and decrypt every thing. However this is (almost) impossible, it is what makes the strength of RSA.

Instead, we will have to try to understand what is exactly happening in term of number theory.

### Using Number theory

For `car` a character of flag (character is written caractère in french), with `n` the noise, is is encrypted as the following:

`encrypt(car) = car^9 + 3 * car^6 * n^1 + 3 * car^3 * n^2 + n^3 mod N`

Fortunately we also have access to  n^3 mod N  which is the first number in ct.
The idea is to compute the following function, by inverting 3 and `car` modulus `N`:

`f(car) := (encrypt(car)  - n^3 - car^9) * 3^-1 * car^-3 mod N` 
`f(car)  = n(n + car^3) mod N`

What is interesting is that if we take the difference of `f` of two characters, it is very small compared to `N`, if `car1 >= car2`:

`f(car1) - f(car2) = n(car1^3 - car2^3)` -> Note that the modulus has disappeared because the number is smaller than `N`.

This number will only takes maximum `(64 * 8 + 24) * 8^3` bits which is very small compared to 1024 for `N`.

The idea is to compute the following function:

`g(car, ct_i) =  (ct_i  - n^3 - car^9) * 3^-1 * car^-3`
we have `g(car, ct_i) = f(car) if ct_i` is the encryption of car. 
We could not compute f because we didn't have access to n, however we can compute g.


### Solution

The solution is the following algorithm:

```python
for car1 in all possible characters:
	for car2 in all possible characters:
		for ct_1 in ct:
			for ct_2 in ct different from ct_1:
				if g(car1, ct_1) - g(car2, ct_2) < ( 1 << (64 * 8 + 24) * 8^3  ):
					car1 is probably the character coded in ct_1
					car2 is probably the character coded in ct_2
```

The four loops might look intimidating, but the complexity was actually `60*60*30*30`, pretty instantaneous.
There are a few false positives but less than 1 in 10, I eliminated them by counting which character was discovered the most often for each ct_i.

Flag: `shkCTF{L0NG_LIV3_N0ISY_RS4_b86040a760e25740477a498855be3c33}`


## Discussion

I believe the creators of the problem had another solution in mind, because this one doesn't use the the fact that `n = m << 24` on the noise. This operation has for consequence that the bits of `n` and `car^3` will be distinct.
