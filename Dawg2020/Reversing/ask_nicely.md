# Ask nicely

## Description

> Remember your manners! 

With a file.

## Solution

We decompile the file with Ghidra, and find the function `flag`:
  
```c
void flag(void)

{
  putchar(0x44);
  putchar(0x61);
  putchar(0x77);
  putchar(0x67);
  putchar(0x43);
  putchar(0x54);
  putchar(0x46);
  putchar(0x7b);
  putchar(0x2b);
  putchar(0x68);
  putchar(0x40);
  putchar(0x6e);
  putchar(0x4b);
  putchar(0x5f);
  putchar(0x59);
  putchar(0x30);
  putchar(0x55);
  putchar(0x7d);
  putchar(10);
  return;
}
```

So I just extract all the hexadecimal characters and give it to https://www.asciitohex.com/.

Flag: `DawgCTF{+h@nK_Y0U}`