# z3_robot

> I made a robot that can only communicate with "z3". He locked himself and now he is asking me for a password !

## Description

We are given a binary. Let's run it.

![robot](../images/robot.png)

The robot asks for a `Passz3rd`. Let's reverse the binary to find the password with Ghidra.

```c
void main(void)
{
  char cVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  undefined8 input;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  input = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf(
        "      \\_/\n     (* *)\n    __)#(__\n   ( )...( )(_)\n   || |_| ||//\n>==() | | ()/\n   _(___)_\n   [-]   [-]   Z3 robot says :"
        );
  puts(pass);
  printf("-> ");
  fflush(stdout);
  fgets((char *)&input,0x19,stdin);
  sVar2 = strcspn((char *)&input,"\n");
  *(undefined *)((long)&input + sVar2) = 0;
  cVar1 = check_flag(&input);
  if (cVar1 == '\x01') {
    puts(
        "      \\_/\n     (* *)\n    __)#(__\n   ( )...( )(_)\n   || |_| ||//\n>==() | | ()/\n   _(___)_\n   [-]   [-]   Z3 robot says :"
        );
    printf("Well done, valdiate with shkCTF{%s}\n",&input);
  }
  else {
    puts(
        "      \\_/\n     (* *)\n    __)#(__\n   ( )...( )(_)\n   || |_| ||//\n>==() | | ()/\n   _(___)_\n   [-]   [-]   Z3 robot says :"
        );
    puts("3Z Z3 z3 zz3 3zz33");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Well this looks intimidating, but actually it is quite simple: the code prints the welcome message, asks for our input (the `fgets` line), replace the `\n` by 0 and pass this string to `check_flag`.

If it is correct, it prints a robot and `Well done, ...`, otherwise it prints the robot and `3Z Z3 z3 zz3 3zz33`.

What about the `check_flag` function?

```c
undefined8 check_flag(byte *param_1)
{
  undefined8 uVar1;
  byte bVar2;
  
  if (((((((((((param_1[0x14] ^ 0x2b) == param_1[7]) &&
             ((int)(char)param_1[0x15] - (int)(char)param_1[3] == -0x14)) &&
            ((char)param_1[2] >> 6 == '\0')) &&
           ((param_1[0xd] == 0x74 && (((int)(char)param_1[0xb] & 0x3fffffffU) == 0x5f)))) &&
          ((bVar2 = (byte)((char)param_1[0x11] >> 7) >> 5,
           (int)(char)param_1[7] >> ((param_1[0x11] + bVar2 & 7) - bVar2 & 0x1f) == 5 &&
           (((param_1[6] ^ 0x53) == param_1[0xe] && (param_1[8] == 0x7a)))))) &&
         ((bVar2 = (byte)((char)param_1[9] >> 7) >> 5,
          (int)(char)param_1[5] << ((param_1[9] + bVar2 & 7) - bVar2 & 0x1f) == 0x188 &&
          (((((int)(char)param_1[0x10] - (int)(char)param_1[7] == 0x14 &&
             (bVar2 = (byte)((char)param_1[0x17] >> 7) >> 5,
             (int)(char)param_1[7] << ((param_1[0x17] + bVar2 & 7) - bVar2 & 0x1f) == 0xbe)) &&
            ((int)(char)param_1[2] - (int)(char)param_1[7] == -0x2b)) &&
           (((param_1[0x15] == 0x5f && ((param_1[2] ^ 0x47) == param_1[3])) &&
            ((*param_1 == 99 && ((param_1[0xd] == 0x74 && ((param_1[0x14] & 0x45) ==0x44)))))))))))
         ) && ((param_1[8] & 0x15) == 0x10)) &&
       (((param_1[0xc] == 0x5f && ((char)param_1[4] >> 4 == '\a')) && (param_1[0xd] == 0x74)))) &&
      (((((bVar2 = (byte)((char)*param_1 >> 7) >> 5,
          (int)(char)*param_1 >> ((*param_1 + bVar2 & 7) - bVar2 & 0x1f) == 0xc &&
          (param_1[10] == 0x5f)) &&
         ((((int)(char)param_1[8] & 0xacU) == 0x28 &&
          ((param_1[0x10] == 0x73 && ((param_1[0x16] & 0x1d) == 0x18)))))) &&
        ((param_1[9] == 0x33 &&
         ((((param_1[5] == 0x31 && (((int)(char)param_1[0x13] & 0x3fffffffU) == 0x72)) &&
           ((char)param_1[0x14] >> 6 == '\x01')) &&
          (((char)param_1[7] >> 1 == '/' && (param_1[1] == 0x6c)))))))) &&
       (((((((char)param_1[3] >> 4 == '\a' &&
            (((param_1[0x13] & 0x49) == 0x40 && (param_1[4] == 0x73)))) &&
           ((param_1[0xb] & param_1[2]) == 0x14)) &&
          (((((*param_1 == 99 && ((int)(char)param_1[5] + (int)(char)param_1[4] == 0xa4)) &&
             (((int)(char)param_1[0xf] & 0x3ffffffU) == 0x5f)) &&
            ((((param_1[10] ^ 0x2b) == param_1[0x11] && ((param_1[0xc] ^ 0x2c) == param_1[4])) &&
             (((int)(char)param_1[0x13] - (int)(char)param_1[0x15] == 0x13 &&
              ((param_1[0xc] == 0x5f && (param_1[0xc] == 0x5f)))))))) &&
           ((char)param_1[0xf] >> 1 == '/')))) &&
         (((param_1[0x13] == 0x72 && ((int)(char)param_1[0x12] + (int)(char)param_1[0x11] ==0xa8))
          && (param_1[0x16] == 0x3a)))) &&
        (((param_1[0x15] & param_1[0x17]) == 9 &&
         (bVar2 = (byte)((char)param_1[0x13] >> 7) >> 5,
         (int)(char)param_1[6] << ((param_1[0x13] + bVar2 & 7) - bVar2 & 0x1f) == 0x18c)))))))) &&
     (((((((int)(char)param_1[7] + (int)(char)param_1[3] == 0xd2 &&
          ((((int)(char)param_1[0x16] & 0xedU) == 0x28 && (((int)(char)param_1[0xc] & 0xacU) ==0xc)
           ))) && ((param_1[0x12] ^ 0x6b) == param_1[0xf])) &&
        ((((((((param_1[0x10] & 0x7a) == 0x72 && ((*param_1 & 0x39) == 0x21)) &&
             ((param_1[6] ^ 0x3c) == param_1[0x15])) &&
            ((param_1[0x14] == 0x74 && (param_1[0x13] == 0x72)))) && (param_1[0xc] == 0x5f)) &&
          (((param_1[2] == 0x34 && (param_1[0x17] == 0x29)) &&
           ((param_1[10] == 0x5f &&
            ((((param_1[9] & param_1[0x16]) == 0x32 &&
              ((int)(char)param_1[2] + (int)(char)param_1[3] == 0xa7)) &&
             ((int)(char)param_1[0x11] - (int)(char)param_1[0xe] == 0x44)))))))) &&
         (((param_1[0x15] == 0x5f && ((param_1[0x13] ^ 0x2d) == param_1[10])) &&
          ((((int)(char)param_1[0xc] & 0x3fffffffU) == 0x5f &&
           (((((param_1[6] & 0x40) != 0 && ((param_1[0x16] & param_1[0xc]) == 0x1a)) &&
             ((bVar2 = (byte)((char)param_1[0x13] >> 7) >> 5,
              (int)(char)param_1[7] << ((param_1[0x13] + bVar2 & 7) - bVar2 & 0x1f) == 0x17c &&
              ((((param_1[0x14] ^ 0x4e) == param_1[0x16] && (param_1[6] == 99)) &&
               (param_1[0xc] == param_1[7])))))) &&
            (((int)(char)param_1[0x13] - (int)(char)param_1[0xd] == -2 &&
             ((char)param_1[0xe] >> 4 == '\x03')))))))))))) &&
       (((param_1[0xc] & 0x38) == 0x18 &&
        (((bVar2 = (byte)((char)param_1[10] >> 7) >> 5,
          (int)(char)param_1[8] << ((param_1[10] + bVar2 & 7) - bVar2 & 0x1f) == 0x3d00 &&
          (param_1[0x14] == 0x74)) &&
         ((bVar2 = (byte)((char)param_1[0x16] >> 7) >> 5,
          (int)(char)param_1[6] >> ((param_1[0x16] + bVar2 & 7) - bVar2 & 0x1f) == 0x18 &&
          (((((int)(char)param_1[0x16] - (int)(char)param_1[5] == 9 &&
             (bVar2 = (byte)((char)param_1[0x16] >> 7) >> 5,
             (int)(char)param_1[7] << ((param_1[0x16] + bVar2 & 7) - bVar2 & 0x1f) == 0x17c)) &&
            (param_1[0x16] == 0x3a)) &&
           ((param_1[0x10] == 0x73 && ((param_1[0x17] ^ 0x1d) == param_1[0x12])))))))))))) &&
      ((((int)(char)param_1[0xe] + (int)(char)param_1[0x17] == 0x59 &&
        (((param_1[2] & param_1[5]) == 0x30 && (((int)(char)param_1[0xf] & 0x9fU) == 0x1f)))) &&
       ((param_1[4] == 0x73 &&
        (((param_1[0x17] ^ 0x4a) == *param_1 && ((param_1[6] ^ 0x3c) == param_1[0xb])))))))))) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
```

This one is really messy, there are a bunch of checks, if they are all true the function returns 1 and 0 otherwise.

No way I'm trying to reverse thoses checks by hand!

## Solution

The challenge description hints for using [Z3](https://github.com/Z3Prover/z3) which is an SMT solver (it solves satisfiability problems). This is exactly what we need here, however it is quite cumbersome to transform the C program into something readable for Z3. Instead I'm using [Angr](https://angr.io/) symbolic execution feature, which is also based on Z3.

Using gdb, I retrieve the addresses of `main`, of the success and of the failure instructions.

```python
import angr

proj = angr.Project('./z3_robot')

state = proj.factory.blank_state(addr=0x401337) # Address of main
good = 0x401329 # Address of print flag
bad = 0x401330 # Address of print failure
simgr = proj.factory.simgr(state)
print(simgr)
print(simgr.active)
print(simgr.explore(find=good,avoid=bad))
s = simgr.found[0]
print(s.posix.dumps(1))

result = s.posix.dumps(0)
print(result)
```

Flag: `shkCTF{cl4ss1c_z3___t0_st4rt_:)}`