# ARMssembly 0

> What integer does this program print with arguments 266134863 and 1592237099?
>
> File: chall.S
>
> Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})

## Description

We are given a .S file, which contains assembly code. Here is an excerpt of the code:
```assembly
	.arch armv8-a
	.file	"chall.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1:
	sub	sp, sp, #16
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 12]
	ldr	w0, [sp, 8]
	cmp	w1, w0
	bls	.L2
	ldr	w0, [sp, 12]
	b	.L3
.L2:
	ldr	w0, [sp, 8]
```

Well it tells us this is an ARMv8 code, so of course we could reverse it using [the specification](https://courses.cs.washington.edu/courses/cse469/19wi/arm64.pdf).

## Solution

But because I am extremely lazy I prefer to compile the code and just execute it.

So I have followed [this guide](https://github.com/joebobmiles/ARMv8ViaLinuxCommandline) to install a cross-compiler to compile the .S code, then install QEMU to emulate ARM and to be able to run the code.

*Disclaimer: this does not work on WSL so I had to fire up a VM.*

First I need to install tools for cross-compiling:

```bash
sudo apt install binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu
```

Then I can compile my file:

```bash
aarch64-linux-gnu-as -o chall.o chall.S
aarch64-linux-gnu-gcc -static -o chall chall.o
```

And yeah, I have an ARMv8 binary!
If I run `file chall` I get the answer `chall: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked`.

If I run it with `./chall` however it does not work, as I can only run it on an ARMv8 environment.
Which is why I use QEMU, which is a virtual machine.

To avoid spinning up a VM, I install it running in the background:
```bash
sudo apt install qemu-user-static
```

And with that I can run `./chall 266134863 1592237099` which answers `Result: 1592237099`.

I convert it to hex and get the flag.

Flag: `picoCTF{5ee79c2b}`