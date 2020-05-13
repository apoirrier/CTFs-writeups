# Simple

> A really simple crackme to get started ;) Your goal is to find the correct input so that the program return 1. The correct input will be the flag.

## Description

We are given an asm file:

```assembly
BITS 64

SECTION .rodata
        some_array db 10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24
        the_second_array db 0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf
        len_second_array equ $ - the_second_array
SECTION .text
    GLOBAL main

main:
        mov rdx, [rsp]
        cmp rdx, 2
        jne exit
        mov rsi, [rsp+0x10]
        mov rdx, rsi
        mov rcx, 0
l1:
        cmp byte [rdx], 0
        je follow_the_label
        inc rcx
        inc rdx
        jmp l1
follow_the_label:
        mov al, byte [rsi+rcx-1]
        mov rdi,  some_array
        mov rdi, [rdi+rcx-1]
        add al, dil
        xor rax, 42
        mov r10, the_second_array
        add r10, rcx
        dec r10
        cmp al, byte [r10]
        jne exit
        dec rcx
        cmp rcx, 0
        jne follow_the_label
win:
        mov rdi, 1
        mov rax, 60
        syscall
exit:
        mov rdi, 0
        mov rax, 60
        syscall
```

The objective is to find the input which returns 1.

## Solution

### Headers

Let's translate this file in regular language.

```assembly
BITS 64

SECTION .rodata
        some_array db 10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24
        the_second_array db 0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf
        len_second_array equ $ - the_second_array
```

This section instantiates two arrays with some data in it.

```assembly
SECTION .text
    GLOBAL main

main:
```

defines the `main` function.

### Reading arguments

```assembly
        mov rdx, [rsp]
        cmp rdx, 2
        jne exit
        mov rsi, [rsp+0x10]
```

Here the code reads the arguments. In C language, `main` function takes two parameters:

```c
int main(int argc, char** argv)
```

`argc` is the number of arguments, `argv` is an array containing the arguments. First argument is always the command used to launch the program.

Therefore this piece of code takes the first argument which is on the stack (pointed by `argc`) and puts its value (the brackets indicate we take the value and not the address `[rsp]`) into register `rdx`. We compare it to 2: if it is not equal, jump to label `exit` which is at the end of `main`.

Otherwise, take the second string of `argv` (we are on 64 bits as indicated at the beginning of the asm file, so each pointer has size 8 bytes) and put it into `rsi`. `rsp` is a pointer to `argc`, `rsp+8` to `argv[0]`, `rsp+0x10` to `argv[1]`. And here, `argv[0]` contains the command to launch the program, `argv[1]` is the argument we give to the program.

Those lines roughly translate as:

```c
int main(int argc, char **argv) {
    if(argc != 2)
        goto exit;
    char* rsi = argv[1];
}
```

### Exit

And the `exit` label:

```
exit:
        mov rdi, 0
        mov rax, 60
        syscall
```

This is a system call. The number of the syscall is given by `rax`. 60 is `exit` (see [list of syscalls](https://filippo.io/linux-syscall-table/)).

The argument passed to `exit` is put into `rdi` (see [argument registers](https://i.stack.imgur.com/eaSf7.jpg)). So this code translates as:

```c
exit(0);
```

Therefore we need to pass exactly one argument. Let's continue.

### Length

```assembly
        mov rdx, rsi
        mov rcx, 0
l1:
        cmp byte [rdx], 0
        je follow_the_label
        inc rcx
        inc rdx
        jmp l1
follow_the_label:
```

At this point, `rsi` is a pointer to our input. We copy this pointer into `rdx`, set `rcx` to zero.

Then, while the value pointed to by `rdx` is not 0 (which is also the code for end of string), we increment `rcx` by one and go to next character.

This code translates as:

```c
char *rdx = rsi;
int rcx = 0;
while(true) {
    if(*rdx == 0)
        break;
    rcx++;
    rdx++;
}
```

At the end of this piece of code, `rcx` holds the length of our input.

### Actual computation

```assembly
follow_the_label:
        mov al, byte [rsi+rcx-1]
        mov rdi,  some_array
        mov rdi, [rdi+rcx-1]
        add al, dil
        xor rax, 42
        mov r10, the_second_array
        add r10, rcx
        dec r10
        cmp al, byte [r10]
        jne exit
        dec rcx
        cmp rcx, 0
        jne follow_the_label
```

When first entering this block, `rsi` contains a pointer to our input and `rcx` the length of our input.

If I were to translate it line by line, without typing the variables (and therefore without casting things), this would give:

```c
label follow_the_label;
    a = rsi[rcx-1]; // mov al, byte [rsi+rcx-1]
    d = some_array[rcx-1]; // mov rdi,  some_array; mov rdi, [rdi+rcx-1]
    a += d; //add al, dil (because dil is low 8 bits of rdi)
    a ^= 42; //al is low 8 bits of rax
    r10 = the_second_array[rcx-1]; // mov r10, the_second_array; add r10, rcx; dec r10;
    if(a != r10) // cmp al, byte [r10]
        goto exit; // jne exit
    rcx--; //dec rcx
    if(rcx != 0) // cmp rcx, 0
        goto follow_the_label; // jne follow_the_label
```

We can write this in more standard C code as:

```c
for(int i=rcx-1; i>=0; --i) {
    int a = (int)(input[i] + some_array[i]) ^ 42;
    if(a != the_second_array[i])
        exit(0);
}
```

### Win

If we pass this loop, we arrive at the `win` label.

```assembly
win:
        mov rdi, 1
        mov rax, 60
        syscall
```

Which translates as `exit(1);`.

### Finding the correct input

Reversing the check part is quite easy, we do this with Python:

```python
some_array = [10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24]
the_second_array = [0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf]

pwd = []
N = len(some_array)

for i in range(N):
    pwd.append((the_second_array[i] ^ 42) - some_array[i])
    
print("".join([chr(x) for x in pwd]))
```

Flag: `shkCTF{h3ll0_fr0m_ASM_my_fr13nd}`