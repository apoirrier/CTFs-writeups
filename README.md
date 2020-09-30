# CTFs-writeups
Writeups for various CTFs competitions

# Tools for CTF
Here is a list to various useful tools for CTF competitions.

## Network

- [Wireshark](https://www.wireshark.org/) to analyze network connections

## Web

- [Postman](https://www.postman.com/) to make HTTP requests
- [OWASP ZAP](https://owasp.org/www-project-zap/) for analysing website security. Features include requests analysis and forgery, fuzzing, etc...
- [sqlmap](http://sqlmap.org/) for automatic SQL injection


## Reverse engineering

- [Ghidra](https://ghidra-sre.org/) to decompile `c` code.
- [Java decompiler](http://www.javadecompilers.com/)
- [gdb](https://www.gnu.org/software/gdb/) a C debugger
- [OllyDbg](http://www.ollydbg.de/) a debugger for Windows programs
- [Android studio](https://developer.android.com/studio) to edit and analyse APK files and emulate APK
- [Apktool](https://ibotpeaches.github.io/Apktool/) for reversing APK files
- [angr](https://angr.io/) for symbolic execution. See [writeup](DarkCTF2020/Reversing/JACK.md).

## PWN

- [pwntools](http://docs.pwntools.com/en/stable/) a Python library for PWN
- [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) search for gadget and ROP chain generation
- [lib search database](https://libc.blukat.me/) for ret2lib. See also [writeup 32 bits](DarkCTF2020/Pwn/newPaX.md) and [writeup 64 bits](DarkCTF2020/Pwn/roprop.md).

## Steganography

- [file](https://linux.die.net/man/1/file) to determine file type
- [strings](https://linux.die.net/man/1/strings) to print all ASCII strings in file
- [binwalk](https://tools.kali.org/forensics/binwalk) to find embedded files
- [StegSolve](https://en.kali.tools/all/?tool=1762) an image solver
- [Steg online](https://stylesuxx.github.io/steganography/#decode) for images
- [Morse decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
- [MMSSTV](https://hamsoft.ca/pages/mmsstv.php) for HAM transmissions
- [Digital Invisible Ink Toolkit](http://diit.sourceforge.net/) for images
- [DeepSound](http://jpinsoft.net/DeepSound/Download.aspx) for sound files
- [Raw Pixels](http://rawpixels.net/) an online RAW image viewer
- [Hexed.it](https://hexed.it/) to edit the bytes of a file

## Forensics
- [Autopsy](https://www.autopsy.com/) for device analysis


## Cryptography

- https://www.dcode.fr/en It knows a lot of common cypher methods and does automatic uncyphering
- [hlextend](https://github.com/stephenbradshaw/hlextend) a Python library for length extension attacks on Merkle-Damgård hash functions
- Factorize big integers with http://factordb.com/

## Password cracking

- [JohntheRipper](https://www.openwall.com/john/)

## OSINT

- [Sherlock](https://github.com/sherlock-project/sherlock) to scrap information on social media

## Misc

- If you know the format of the flag, you can use `flag_converter.py` to quickly have the most common encoding of the flag, so you know what to look for during the competition ;)
- https://www.asciitohex.com/  For quick conversion between ASCII, decimal, base64, binary, hexadecimal and URL
- https://gchq.github.io/CyberChef/ Same as asciitohex but more complete, with magic wand.
- https://upload.wikimedia.org/wikipedia/commons/d/dd/ASCII-Table.svg: An Ascci to decimal, hexadecimal, binary and octal table
- Deal with images in Python using [PIL](https://pillow.readthedocs.io/en/stable/). See [example writeup](DarkCTF2020/Misc/QuickFix.md)


# Writeups from other people

This file holds some links to tasks I have failed in the past and whose writeup may be helpful later.

## Pwn

- Some task with Python bytecode: [Puffer Overflow](https://ctftime.org/task/11928)

## Crypto

- Ciphertexts with unknown but classical cipher: [Video](https://www.youtube.com/watch?v=9Q5Q1Nn5Vss)
- Hill cipher solver: [Embrace the Climb](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Embrace%20the%20Climb#embrace-the-climb-)


## Misc

- Some task with an Arduino compiled binary: [A Flash of Inspiration](https://ctftime.org/task/11930)
- Blockchain: [Bitcoin transaction vulnerability](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Duplicacy%20Within#duplicacy-within)
