# Clutter

> > Out of clutter, find simplicity.
> 
> Un de vos collègues vous a envoyé un programme qu'il a développé et souhaite vous défier.
>
> Validez votre accès et fournissez-lui le flag.

## Description

This one was a mess.
I opened the file with Ghidra, found the `main` function and then processed to fix all the wrong disassembly of Ghidra (mostly wrong functions calls and typing of arguments).

There is a global data array of 64 integers that I called `DAT`, an local integer that I called `fct` initialized to `DAT[9]` and a local integer that I called `state` initialized to `0x13`.

The main function is composed of a `while(True)` loop, where at each iteration of the loop, some action is performed depending of the value of the `fct` variable (as if they were inline functions), similarly to a state machine.

I also renamed some functions like `ror1f, rol1f, strange[Operation]...` but they actually don't really matter.

I will list all those inline functions here:

### fct == 0x6ca7afa7

```c
DAT[10] = 9;
state = 0x79;
fct = 0x6a09e667;
```

Basically changes `DAT[10]` to 9 and jumps to the next state.

### fct == 0x679dfce7

```c
for (i = 0x10; (int)i < 0x40; i = i + 1) {
    iVar3 = strangeXor10(DAT[(int)(i + -2)]);
    uVar6 = DAT[(int)(i + -7)];
    iVar4 = strangeXor3(DAT[(int)(i + -0xf)]);
    DAT[(int)i] = iVar3 + uVar6 + iVar4 + DAT[(int)(i + -0x10)];
}
uVar2 = strangeXor3(0x679dfce7);
uVar5 = rol1f(state,7);
uVar6 = ror1f((uint)state,9);
state = strangeDiff(DAT[uVar6 & 0x3f],uVar5,uVar2);
fct = DAT[9];
```

This one changes the values of all `DAT[i]` for `i >= 0x10` depending on the values already there, then compute a new state and jump to the node `DAT[9]`.

### fct == 0x66cbba27

```c
fct = 0x6a09e667;
```

Just a jump.

### fct == 0x6a09e667

```c
uVar2 = ror1f(((uint)(state >> 6) | (uint)state << 2) ^
                ((uint)(state >> 7) | (uint)state * 2),8);
bVar1 = strangeXOR0(0xc3a65999);
state = (state ^ bVar1) & 0x3f;
fct = strangeXor3(uVar2);
fct = fct ^ 0x6a09e667
```

This function redirects to a node depending on the value of the state.

### fct == 0x6ac7a3a7

```c
DAT[DAT[10] & 0xf] = DAT[DAT[10] & 0xf] ^ DAT[DAT[10] + 1 & 0xf];
state = 0x68;
fct = 0x6a09e667;
```

It performs `DAT[DAT[10]] ^= DAT[DAT[10]+1]`

### fct == 0x70b9d067

```c
if (DAT[10] == 0) {
    fct = DAT[0];
}
else {
    DAT[10] = DAT[10] - 1;
    state = 0x79;
    fct = 0x6a09e667;
}
```

This one implements kind of a switch logic: if `DAT[10]` is zero then goto `DAT[0]` else goto next state and decrement `DAT[10]`.

### fct == 0x78b38527

```c
state = (byte)DAT[(int)(state - 10)];
if ((arguments[0] < DAT[(int)((state ^ 4) & 0xf)]) && (arguments[0] != 0)) {
    iVar3 = gcd(DAT[(int)((state ^ 4) & 0xf)],arguments[0]);
    DAT[(int)((state ^ 4) & 0xf)] = iVar3 - 1;
    for (i = 0; (int)i < 4; i = i + 1) {
    local_38[(int)i] =
            (char)((0xff << ((byte)(i << 3) & 0x1f) & arguments[1]) >> ((byte)(i << 3) & 0x1f))
    ;
    }
    if (((((local_38[3] & 0xfU) == local_38[3]) && ((local_38[2] & 0xfU) == local_38[2])) &&
        ((local_38[1] & 0xfU) == local_38[1])) &&
        ((((local_38[0] & 0xfU) == local_38[0] && ((byte)local_38[2] < (byte)local_38[3])) &&
        (((byte)local_38[1] < (byte)local_38[2] && ((byte)local_38[0] < (byte)local_38[1])))))
        ) {
    DAT[(int)((state ^ 7) & 0xf)] =
            DAT[(int)(uint)(byte)local_38[3]] ^ DAT[(int)(uint)(byte)local_38[2]] ^
            DAT[(int)(uint)(byte)local_38[1]] ^ DAT[(int)(local_38 & 0xff)];
    DAT[(int)((state ^ 4) & 0xf)] = arguments[0];
    fct = 0x6a09e667;
    }
    else {
    state = 0xdb;
    fct = 0x66cbba27;
    }
}
else {
    state = 0xea;
    fct = 0x66cbba27;
}
```

Definitely a complex function.
First it changes the state.

Let's call `a = ((state ^ 4) & 0xf)` and `b = ((state ^ 7) & 0xf)`.

Then this function performs the following:
1) `DAT[a] = gcd(DAT[a], arguments[0]) - 1`
2) it extracts the 4 bytes out of `arguments[1]` and puts them in `local38`.
3) it verifies that each byte is smaller than 16 and that they are in strictly increasing order. Let's call the 4 numbers `x,y,z,t`.
4) `DAT[b] = DAT[x] ^ DAT[y] ^ DAT[z] ^ DAT[t]`
5) `DAT[a] = arguments[0]`

And then jump to a next stage.

### fct == 0xdeadbeef

```c
if (state == 0x28) {
    DAT[9] = fct;
    state = 0x13;
    fct = 0x6a09e667;
}
else {
    if (DAT[63] == 0xa3efa1d) {
    printf("Congrats!\nHere is your flag: DGA{%x_%x}\n",arguments & 0xffffffff,
            arguments >> 0x20);
    return 0;
    }
    fct = 0xdeaddead;
    state = 0;
}
```

This is our winning function, but we also need `DAT[63]` to have the correct value.

### fct == 0x6df725a7
```c
if ((uint)argc < 3) {
    state = 100;
}
else {
for (i = 1; i < 3; i = i + 1) {
    uVar7 = strtoul(argv[(int)i],(char **)0x0,0x10);
    arguments[(int)(i - 1)] = (uint)uVar7;
}
state = 0x42;
}
fct = 0x6a09e667;
```

This is the function reading our arguments. There needs to be two integers written as hexadecimal.

## Further analysis

With all the jumps everywhere, I needed to figure out how those functions interact.
Most functions will return to the `0x6a09e667` function by setting first the `state` parameter.

Thus `0x6a09e667` is some kind of crossroad function, and I figured out the following relations:

| From function (state) | Destination, new_state | Side-effect |
|:---------------------:|:----------------------:|:----------:|
From start (0x13) | go to 0x679dfce7, 0x1f |
From 0x6ca7afa7 (0x79) | go to 0x6ac7a3a7, 0x35 | I = 9
From 0x6ac7a3a7 (0x68) | go to 0x66cbba27, 0x24 | DAT[i] ^= DAT[I+1]
From 0x66cbba27 (0x24) | go to 0x70b9d067, 0x28 |
From 0x70b9d067 (0x79) | go to 0x6ac7a3a7, 0x35 | if I == 0: goto DAT[0] else I -= 1

From this array we see that once the `0x6ca7afa7` function is reached, a loop occurs that xors successively the lowest values of `DAT` and goes to the result of this XOR.

From the start function, I jump to the `0x679dfce7` function which changes the values in `DAT`, then it goes read the 2 arguments.

Then it goes to `0x78b38527` which processes my arguments. If some check inside this function fails, the program stops.
Moreover, for the value of the arguments `a=5` and `b=6`.

Otherwise it goes to the `0x6ca7afa7` function, thus starting the xor operation.

From there I saw no easy-going way to the win function. That means that to win, I would need to provide the correct input such that the xor of the first `DAT` values will lead me to `0xdeadbeef`.

Recall hopefully that thanks to the step 5 of `0x78b38527`, I control `DAT[5]` as it is set to `arguments[0]`.
Thus I can always reach `0xdeadbeef`, but I need to find the correct `arguments[1]` to get the flag.

As there are not a lot of choices (the number of combinations of 4 elements in [0..15]), I can brute force them all.

## Summary

The program initialises some state, then reads my arguments and go through the `0x78b38527` subfunction.
In this function, it changes the values of `DAT[6]` to be the XOR of 4 different values in `DAT[0..15]`.
Then finally I can choose the value of `DAT[5]` such that the program reaches the winning function (as the next reached address is decided by xoring the first 10 values).

My solution is to brute force the 4 values chosen, from this deduce the first argument I need to provide and test if it yields the flag.

The following script does this:

```python
import itertools
import subprocess

DATA2 = [
0x1b752973,      0x8f408722,      0x5ef9e954,      0x962cd4d3,
0x77459271,      0,      0x7c039e7b,      0xd98f3cbf,
0xe0300990,      0x6a09e667,      0x70715969,      0x35744deb,
0xc20a3236,      0x78ddea09,      0xf4543275,      0x028a811d,
] # Replaced DAT[5] with 0 as it will be in the program

for candidate in itertools.combinations(range(16), 4):
    x = 0xdeadbeef # Win function
    for i in range(10):
        x ^= DATA2[i]
    x ^= DATA2[6] # Remove DATA2[6] from the XOR computation as it will be replaced
    x ^= 9 # Value of DATA[10] when XOR happens
    for c in candidate:
        x ^= DATA2[c]
    process = subprocess.run(["./dghack2021-clutter", hex(x)[2:], "0{}0{}0{}0{}".format(hex(candidate[3])[2:], hex(candidate[2])[2:], hex(candidate[1])[2:], hex(candidate[0])[2:])], capture_output=True)
    if b"Congrats" in process.stdout:
        print(process.stdout)
        break
```

where I copied `DATA2` from memory while running gdb, before the processing of my arguments.

Flag: `DGA{e302c75d_8070605}`