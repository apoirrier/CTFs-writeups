# BabyMIPS
Reverse Engineering

## Description

> What's the flag?

Attached is a binary file

## Solution

Using [Ghidra](https://ghidra-sre.org/) to reverse the binary file, we obtain the following code for main:
```c

undefined4 main(void)

{
  basic_ostream *this;
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack152 [24];
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack128 [24];
  undefined auStack104 [84];
  int iStack20;
  
  iStack20 = __stack_chk_guard;
  basic_string();
                    /* try { // try from 00400e44 to 00400edb has its CatchHandler @ 00400f80 */
  this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"enter the flag");
  operator<<((basic_ostream<char,std--char_traits<char>>*)this,endl<char,std--char_traits<char>>);
  operator>><char,std--char_traits<char>,std--allocator<char>>
            ((basic_istream *)&cin,(basic_string *)abStack152);
  memcpy(auStack104,&UNK_004015f4,0x54);
  basic_string((basic_string *)abStack128);
                    /* try { // try from 00400ef0 to 00400ef7 has its CatchHandler @ 00400f54 */
  FUN_00401164(auStack104,abStack128);
  ~basic_string(abStack128);
  ~basic_string(abStack152);
  if (iStack20 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Meaning the flag is encoded in memory at address ```UNK_004015f4```, the main function asks the user to enter a string, and calls ```FUN_00401164``` with the first argument being the encoded flag and the second argument what the user entered.

Code for ```FUN_00401164```:
```c
void FUN_00401164(int param_1,
                 basic_string<char,std--char_traits<char>,std--allocator<char>> *param_2)

{
  int iVar1;
  basic_ostream *this;
  uint uVar2;
  char *pcVar3;
  uint uStack20;
  
  iVar1 = size();
  if (iVar1 == 0x4e) {
    uStack20 = 0;
    while (uVar2 = size(), uStack20 < uVar2) {
      pcVar3 = (char *)operator[](param_2,uStack20);
      if (((int)*pcVar3 ^ uStack20 + 0x17) != (int)*(char *)(param_1 + uStack20)) {
        this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
        return;
      }
      uStack20 = uStack20 + 1;
    }
    this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"correct!");
    operator<<((basic_ostream<char,std--char_traits<char>>*)this,endl<char,std--char_traits<char>>)
    ;
  }
  else {
    this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");
    operator<<((basic_ostream<char,std--char_traits<char>>*)this,endl<char,std--char_traits<char>>)
    ;
  }
  return;
}
```

The flag has size 0x4e = 78 characters, and the function prints correct only if for every character:
```
userInput[i] XOR (i + 0x17) == encoded_flag[i]
```
(by convention, the addition has higher priority then XOR).

We can retrieve the encoded flag in the memory thanks to Ghidra, and then this Python scripts decodes the flag:
```python
with open("secret.txt", "r") as f:
    j = 0
    for l in f:
        i = int(l[:2], 16)
        i ^= (j + 0x17)
        print(chr(i), end="")
        j += 1
```
Flag: utflag{mips_cpp_gang_5VDm:~`N]ze;\)5%vZ=C'C(r#$q=*efD"ZNY_GX>6&sn.wF8$v*mvA@'}