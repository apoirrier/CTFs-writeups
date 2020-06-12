# Teleport

> One of our admins plays a strange game which can be accessed over TCP. He's been playing for a while but can't get the flag! See if you can help him out.

We can connect to a remote server, and the source is given:

```python
import math

x = 0.0
z = 0.0
flag_x = 10000000000000.0
flag_z = 10000000000000.0
print("Your player is at 0,0")
print("The flag is at 10000000000000, 10000000000000")
print("Enter your next position in the form x,y")
print("You can move a maximum of 10 metres at a time")
for _ in range(100):
    print(f"Current position: {x}, {z}")
    try:
        move = input("Enter next position(maximum distance of 10): ").split(",")
        new_x = float(move[0])
        new_z = float(move[1])
    except Exception:
        continue
    diff_x = new_x - x
    diff_z = new_z - z
    dist = math.sqrt(diff_x ** 2 + diff_z ** 2)
    if dist > 10:
        print("You moved too far")
    else:
        x = new_x
        z = new_z
    if x == 10000000000000 and z == 10000000000000:
        print("ractf{#####################}")
        break
```

## Description

We get a Python code, and we need to move to the flag. We are originally at position `(0,0)`, can move only of at most `10`, and need to get to `(10000000000000, 10000000000000)` in less than 100 movements. In other words: we need to break the code.

When we enter a string, it is split with `,`, then each part is converted to float. If an exception happens, we reach `continue` and can try again.

If the string translates correctly, then those are our new coordinates, and a check is performed using `math.sqrt` to verify the new position is not too far from the previous one. If not, we reach the new coordinates.

## Solution

My first thought was to try to pwn the program by using the `input` function, which is vulnerable in Python 2. However, the syntax suggest Python 3, so this did not work. 

Then I tried to overflow the float, but this does not work either as in Python, overflows produce an exception.

The solution found was to use special value `nan` (Not a number), which is interpreted as float in Python. Moreover, `float('nan') > 10` is `False` as `nan` cannot be compared to numbers.

Therefore the exploit is as follow:
- first send `nan, nan`. The new position will be `nan, nan`
- second send `10000000000000, 10000000000000`. We reach the flag.

Flag: `ractf{fl0at1ng_p01nt_15_h4rd}`