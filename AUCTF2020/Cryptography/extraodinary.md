# Extraordinary

## Description

> On their way back from the market, Alice and Bob noticed a little device on the ground. Next to it was a piece of paper with what looked like a bunch of scrambled numbers on it. It looked completely random. They took it to the lost and found, but on their way they played with it a little bit (don't tell anyone!). The device was never picked up, so we get to play with it a little bit, too. Can you figure out how the device works?
>
> `b'6\x1d\x0cT*\x12\x18V\x05\x13c1R\x07u#\x021Jq\x05\x02n\x03t%1\\\x04@V7P\\\x17aN'`
>
> `nc challenges.auctf.com 30030`

## Solution

On the sever, it lets us input a string then gives us an encoded string. If we give it `auctf` tge return string is empty. From there we understand that the encryption is a XOR.

To solve it I give as input a string of `a`s, it gives me the encoded string `all_a_encoded`. I can then do a XOR betzeen this string and `a`s, character by character, which gives us the XOR key, `uctf{n3v3R_r3Us3_y0uR_0Tp_872vc8972}uctf{n3v3R_r3Us3_y` (missing the first `a`).

```python
all_a_encoded = b'\x14\x02\x15\x07\x1a\x0fR\x17R3>\x13R4\x12R>\x18Q\x143>Q5\x11>YVS\x17\x02YXVS\x1c\x14\x02\x15\x07\x1a\x0fR\x17R3>\x13R4\x12R>\x18'

key = [chr(c^ord('a')) for c in all_a_encoded]
print(''.join(key))
```

This solution doesn't use the given string.

Flag: `auctf{n3v3R_r3Us3_y0uR_0Tp_872vc8972}`