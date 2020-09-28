# JACK

> Just another crackme....
>
> Enclose the key with darkCTF{}

Attached is a binary file.

## Description

We reverse it with Ghidra.

```c
ulong main(void)
{
  uint uVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  char local_28;
  char local_27;
  char local_26;
  char local_25;
  char local_24;
  char local_23;
  char local_22;
  char local_21;
  char local_20;
  char local_1f;
  char local_1e;
  char local_1d;
  char local_1c;
  char local_1b;
  char local_1a;
  char local_19;
  undefined local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Enter your key: ");
  fgets(&local_28,0x11,stdin);
  local_18 = 0;
  sVar2 = strlen(&local_28);
  if (sVar2 != 0x10) {
    puts("Try Harder");
  }
  else {
    local_38 = (int)local_25 * 0x1000000 +
               (int)local_28 + (int)local_27 * 0x100 + (int)local_26 * 0x10000;
    local_38 = local_38 ^ ((int)local_38 >> 3 & 0x20000000U) + local_38 * 0x20;
    local_38 = local_38 ^ local_38 << 7;
    local_38 = (local_38 >> 1 & 0xff) + local_38;
    local_38 = ((int)local_38 >> 3 & 0x20000000U) + local_38 * 0x20 ^ local_38;
    local_38 = local_38 ^ local_38 << 7;
    local_38 = local_38 + (local_38 >> 1 & 0xff);
    uVar1 = (int)local_21 * 0x1000000 +
            (int)local_24 + (int)local_23 * 0x100 + (int)local_22 * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_34 = uVar1 + (uVar1 >> 1 & 0xff);
    uVar1 = (int)local_1d * 0x1000000 +
            (int)local_20 + (int)local_1f * 0x100 + (int)local_1e * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_30 = uVar1 + (uVar1 >> 1 & 0xff);
    uVar1 = (int)local_19 * 0x1000000 +
            (int)local_1c + (int)local_1b * 0x100 + (int)local_1a * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_2c = uVar1 + (uVar1 >> 1 & 0xff);
    check_flag(&local_38);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return (ulong)(sVar2 != 0x10);
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


/* check_flag(unsigned int*) */

void check_flag(uint *param_1)

{
  if ((((*param_1 == 0xcb9f59b7) && (param_1[1] == 0x5b90f617)) && (param_1[2] == 0x20e59633)) &&
     (param_1[3] == 0x102fd1da)) {
    puts("Good Work!");
    return;
  }
  puts("Try Harder");
  return;
}
```

We need to enter a 16 character key, which undertakes quite a lot of complicated modifications before being compared to static values. This is a perfect exemple where symbolic execution will help to find the flag.

## Solution

Let's use angr to find the password.

```python
#!/usr/bin/env python3
import angr, time, claripy

BINARY='./jack'
OUTFILE='out'
t=time.time()
proj = angr.Project(BINARY, auto_load_libs=False)
print(proj.arch)
print(proj.filename)
print("Entry: 0x%x" % proj.entry)

password = claripy.BVS("flag", 8*16)
state = proj.factory.entry_state(args=[BINARY, OUTFILE], stdin=password)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Good Work!" in s.posix.dumps(1), avoid=lambda s: b"Try harder" in s.posix.dumps(1))

print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")

```

Flag: `darkCTF{n0_5ymb0l1c,3x30}`
