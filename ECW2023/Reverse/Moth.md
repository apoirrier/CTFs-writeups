# Moth

> Find the correct entry.

## Description

Let's reverse this program using Ghidra.

I find the address of the `main` function as the first argument of `__libc_start_main` in the `entry` function.

Here is the decompiled code:

```c
int main(int argc,char **argv)

{
  int iVar1;
  size_t sVar2;
  
  if (argc == 2) {
    sVar2 = strlen(argv[1]);
    if ((sVar2 == 0x51) && (iVar1 = FUN_001011cd(argv[1]), iVar1 != 0)) {
      puts("Well done, flag is ECW{md5(input)}");
      return 0;
    }
    puts("Nope");
  }
  return 1;
}
```

The input is provided as first argument on the command line, should be 0x51 bytes long, and `FUN_001011cd(input)` should be non zero.

With this easy program, it should be able to use static analysis to get constraints, using `angr` for example, but for some reason I didn't manage to make it work.

Thus, I reversed the function by hand.

## Reversing the function

Let's understand what the `FUN_001011cd` function does.
The following extract is the reversed code from Ghidra with some variables renamed for clarity.

```c

bool FUN_001011cd(long param_1)

{
  char cVar1;
  int iVar2;
  uint current_ret;
  int i;
  int j;
  int x;
  int y;
  int delta_i;
  int delta_j;
  int ret;
  int k;
  char current_char;
  
  current_ret = 0;
  i = 0;
  do {
    if (8 < i) {
      ret = 0;
      for (k = 0; k < 3; k = k + 1) {
        ret = ret + ((int)current_ret >> ((byte)k & 0x1f) & 1U);
      }
      return ret == 0;
    }
    for (j = 0; j < 9; j = j + 1) {
      current_char = *(char *)(param_1 + (j + i * 9));
      if ((current_char < 'a') || ('e' < current_char)) {
        return false;
      }
      cVar1 = (&DAT_00102020)[j + i * 9];
      iVar2 = FUN_00101169((int)cVar1);
      if (iVar2 < current_char + -0x60) {
        current_ret = current_ret | 1;
      }
      for (x = 0; x < 9; x = x + 1) {
        for (y = 0; y < 9; y = y + 1) {
          if ((((y != j) || (x != i)) && (cVar1 == (&DAT_00102020)[y + x * 9])) &&
             (current_char == *(char *)(param_1 + (y + x * 9)))) {
            current_ret = current_ret | 2;
          }
        }
      }
      for (delta_i = -1; delta_i < 2; delta_i = delta_i + 1) {
        for (delta_j = -1; delta_j < 2; delta_j = delta_j + 1) {
          if (((((-1 < delta_j + j) && (-1 < delta_i + i)) &&
               ((delta_j + j < 9 && (delta_i + i < 9)))) && ((delta_j != 0 || (delta_i != 0)))) &&
             (current_char == *(char *)(param_1 + (delta_j + j + (i + delta_i) * 9)))) {
            current_ret = current_ret | 4;
          }
        }
      }
    }
    i = i + 1;
  } while( true );
}
```

To get the flag, the function needs to return 0.
We can see that there is a main double loop (with variables `i` and `j`, which retrieve the character `j+i*9` from the input string).

This `current_char` then undergoes four tests:
- first, a test which checks if it is a character between `'a'` and `'e'`, and if it is not, it fails the function;
- second, a test involving the constant `(&DAT_00102020)[j + i * 9]` and `FUN_00101169`;
- a third test with loops on `x` and `y`;
- and a last test with loops `delta_x` and `delta_y`.

Each of those tests put `current_ret` to a non-zero value, which then leads to a non zero `ret` value, and thus a failure.

### First test

`FUN_00101169` is the following function:
```c
int FUN_00101169(char param_1)
{
  int ret;
  int i;
  int j;
  
  ret = 0;
  for (i = 0; i < 9; i = i + 1) {
    for (j = 0; j < 9; j = j + 1) {
      if (param_1 == (&DAT_00102020)[j + i * 9]) {
        ret = ret + 1;
      }
    }
  }
  return ret;
}
```

Given its input parameter `param_1`, it returns the number of times `DAT_00102020[i,j]` is equal to `param_1`.

If there are `z` such numbers, then our input character should not be greater than `'a' + z`.

### Second test

The second test function verifies that for all `x,y`, if `DAT_00102020[i,j] == DAT_00102020[x,y]`, then `input[i,j]` should be different than `input[x,y]`.

In other words, `DAT_00102020` links indices such as all cells with `DAT_00102020[x,y]` having the same value should be all different.

### Third test

The third test gives us the last constraints on cells: adjacent cells (in the 2D matrix) should not have the same value.

## Finding a solution

I used `claripy` to recreate the problem and add the constraints. 

Here is the complete Python code:

```python
import claripy

data = [ 0x01, 0x01, 0x01, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x01, 0x07, 0x02, 0x02, 0x03, 0x04, 0x04, 0x05, 0x06, 0x07, 0x07, 0x07, 0x02, 0x02, 0x08, 0x04, 0x05, 0x06, 0x07, 0x09, 0x09, 0x09, 0x09, 0x08, 0x04, 0x05, 0x06, 0x0a, 0x09, 0x0b, 0x0b, 0x08, 0x08, 0x08, 0x0d, 0x0a, 0x0a, 0x0a, 0x0c, 0x0b, 0x0b, 0x0e, 0x0d, 0x0d, 0x0a, 0x0f, 0x0f, 0x0c, 0x0b, 0x0e, 0x0e, 0x0e, 0x0d, 0x10, 0x0f, 0x0f, 0x0f, 0x12, 0x13, 0x13, 0x13, 0x0d, 0x10, 0x10, 0x11, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ][:0x51]

def FUN_00101169(x):
    res = 0
    for i in range(9):
        for j in range(9):
            if x == data[i+j*9]:
                res += 1
    return res

variables = [claripy.BVS(f'var{i}', 8) for i in range(0x51)]
s = claripy.Solver()

for i,x in enumerate(variables):
    s.add(x >= claripy.BVV(1, 8))
    s.add(x <= claripy.BVV(FUN_00101169(data[i]), 8))

for i in range(0x51):
    for j in range(i+1,0x51):
        if data[i] == data[j]:
            s.add(variables[i] != variables[j])

for i in range(9):
    for j in range(9):
        for x in range(-1,2):
            for y in range(-1,2):
                if (x != 0 or y != 0) and i+x >= 0 and i+x < 9 and j+y >= 0 and j+y < 9:
                    s.add(variables[i*9+j] != variables[(i+x)*9+j+y])

print(s.satisfiable())
flag = ""
for x in variables:
    flag += chr(0x60+s.eval(x, 1)[0])
print(flag)
```

Solution: `bcaedbabaadbcacdcdbcadbebabdebecaceccadadedabdbebcbcedcacaedababebdbcedcacacedaba`

Flag: `ECW{8b39553c944cdce4ea4f9a692168093b}`