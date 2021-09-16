# CTFs-writeups
Writeups for various CTFs competitions


# Example of writeups

## Blockchain

### Eth

- [Blockchain transactions are public (ETH)](SharkyCTF2020/Blockchain/Guessing.md)
- [Reentrancy exploit](SharkyCTF2020/Blockchain/Multipass.md)

### Bitcoin

- [Bitcoin transaction vulnerability](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Duplicacy%20Within#duplicacy-within)

## Cryptography

### Easy crypto

- [OTP reuse](UTCTF2020/One%20True%20Problem.md)
- [Morse from audio](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
- [Enigma](BrigitteFriang/Crypte.md)
- [Lot of guessy ciphertexts without knowledge of cipher](https://www.youtube.com/watch?v=9Q5Q1Nn5Vss)
- [Hill cipher](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Embrace%20the%20Climb#embrace-the-climb-)

### AES

- [Malleability of the first block in AES-CBC](AwesomeCTF2020/Crypto/Access.md)
- [Padding oracle attack on AES-CBC](SharkyCTF2020/Crypto/Backflip.md)
- [IV recovery with partially known plaintext, ciphertext and key in AES-CBC](TMUCTF2021/Crypto/435!.md)

### RSA
- [RSA with ciphertext super small](CSAWQual2021/crypto/GottaDecryptThemAll.md)
- [Attacks on RSA: Wiener, sexy primes, LSB oracle, partial private key leaked](CSAWQual2021/crypto/RSAPopQuiz.md)
- [Multi-primes RSA](TMUCTF2021/Crypto/CommonFactor.md)

### Hashes
- [Hash length extension attack](TAMUCTF2020/Crypto/Eternal%20Game.md)

### Cryptography in subgroups of Z or Z*

- [DLP, order of N has small factors](BrigitteFriang/LeDiscretNapier.md)
- [ElGamal signature scheme without hash existential forgery](CSAWQual2021/crypto/Forgery.md)
- [Break DH key exchange with Pohlig-Hellman attack for DLP](TJCTF2020/Cryptography/DifficultDecryption.md)

### Elliptic curves

- [CRT on EC points](BrigitteFriang/VXElliptique.md)

### Bad randomness
- [Retrieve state of java.util.Random PRNG](SharkyCTF2020/Crypto/Casino.md)

### Esoteric

- [Custom VHDL cipher on FPGA](BrigitteFriang/EvilCipher.md)
- [Hardware AES key, CRT, Galois fields](BrigitteFriang/crypto.md)


## Forensics

### Images

- [Broken JPEG header](AwesomeCTF2020/Forensics/CheapFacades.md)
- [Broken PNG image](AwesomeCTF2020/Forensics/Dimensionless.md)
- [Broken BMP header](PicoCTF/Forensics/tunn3l_v1s10n.md)
- [Flag hidden in bit plane of image](Dawg2020/Forensics/UMBCShield.md)
- [Image manipulation with PIL](TJCTF2020/Forensics/Unimportant.md)

### Audio

- [binwalk and flag hidden in spectrogram of audio file](AwesomeCTF2020/Forensics/MonsterIssue.md)
- [UART](BrigitteFriang/ASCII_UART.md)
- [SSTV](UTCTF2020/1%20Frame%20per%20Minute.md)

### Network files

- [Scapy to read pcap](CSAWQual2021/ics/APainInTheBacnet.md)

### Dump files

- [Android dump position history](BrigitteFriang/Ocean.md)
- [Arduino](https://ctftime.org/writeup/21344)

### Esoteric

- [Keypad sniffer](BrigitteFriang/KeypadSniffer.md)
- [Polyglotte files](BrigitteFriang/Polyglotte.md)
- [Hidden flag in RSA parameter](BrigitteFriang/Stranger.md)
- [Detect falsified data with Benford's law](Dawg2020/Forensics/benford_law_firm.md)
- [Automating decompression with password cracking](HouseplantCTF2020/Misc/Zip.md)
- [Read sparse files](SharkyCTF2020/Misc/My-huge-file.md)
- [Color hex values](TJCTF2020/Forensics/Hexillogy.md)



## Misc
- [Bypass float comparison in Python](AwesomeCTF2020/Misc/Teleport.md)
- [Read QR code with Python](HouseplantCTF2020/Web/QRGenerator.md)
- [Python bytecode](https://ypl.coffee/ractf-2020-puffer-overflow/)

## OSINT

- [Github older commit](AUCTF2020/OSINT/WhoMadeMe.md)
- [Old version of pip library](AwesomeCTF2020/Misc/Spentalkux.md)
- [Find password of an employee in social network](Dawg2020/Forensics/ImpossiblePenTest.md)

## PWN

### Buffer overflow

- [Simple buffer overflow](AUCTF2020/PWN/ThanksgivingDinner.md)
- [32 bits ROP chain buffer overflow](AUCTF2020/PWN/HouseofMadness.md)
- [NX disabled](TJCTF2020/Pwn/ElPrimo.md)

### Simple format string

- [Format string vulnerability to bypass canary and PIE for buffer overflow](AwesomeCTF2020/PWN/FinchesPIE.md)
- [GOT override with format string vulnerability (no PIE)](AwesomeCTF2020/PWN/NRA.md)

### ret2lib

- [32 bit ret2lib with buffer overflow](DarkCTF2020/Pwn/newPaX.md)
- [64 bit ret2lib with buffer overflow](DarkCTF2020/Pwn/roprop.md)
- [ret2lib with ASLR and PIE with only format string vulnerabilities](https://github.com/KrauseBerg/CTF-writeups-1/blob/patch-1/CSAW%602021/procrastination.py)

### Break PRNG

- [Guess randomness of rand with srand(time)](CSAWQual2021/pwn/haySTACK.md)

### Privilege escalation

- [Privilege escalation on Linux machine, exit rbash](BrigitteFriang/AloneMusk.md)

### Heap exploitation

- [Reallocate chosen freed block from tcache](https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Cache_Me_Outside.md)


## Password cracking

- [Simple john](AUCTF2020/Password_Cracking/Crackme.md)
- [Salted hash](AUCTF2020/Password_Cracking/Salty.md)
- [Custom List](AUCTF2020/Password_Cracking/Mental.md)
- [KDBX](AUCTF2020/Password_Cracking/Manager.md)
- [ZIP](AUCTF2020/Password_Cracking/Zippy.md)

## Quantum

- [Quantum key distribution](https://ctf.zeyu2001.com/2021/csaw-ctf-qualification-round-2021/save-the-tristate)

## Reversing

- [Java decompiler](AUCTF2020/Reversing/MrGameAndWatch.md)
- [Assembly reversing](AUCTF2020/Reversing/PlainJane.md)
- [ARMv8 assembly reversing](PicoCTF/Reversing/ARMssembly0.md)
- [Use angr to crack password](DarkCTF2020/Reversing/JACK.md)

## Web

### PHP and JS simple vulnerabilities

- [PHP injection with eval used](AUCTF2020/Web/quick_maths.md)
- [Exploit javascript equality check to bypass hash collision](AwesomeCTF2020/Web/C0llide.md)

### SQL attacks

- [Blind SQLi, path transversal](AwesomeCTF2020/Web/Quarantine.md)
- [Another blind SQLi](TAMUCTF2020/Web/Password_extraction.md)
- [SQL union attack, weak new password procedure](BrigitteFriang/web.md)

### JWT
- [disable JWT signing](AwesomeCTF2020/Web/Quarantine.md)
- [JWT with RS256 and weak RSA key](TMUCTF2021/Web/TheDevilNeverSleeps.md)

### RCE with SSTI

- [Jinja2 SSTI](CSAWQual2021/web/ninja.md)

### XSS

- [Reflected XSS](DGHack2020/Web/InternalSupport.md)
- [Reflected XSS with older version of browser (SameSite=None)](DGHack2020/Web/UpCredit.md)
- [Bypass WAF for reflected XSS](TJCTF2020/Web/AdminSecrets.md)

### Proxy stuff

- [Bypass nginx deny-all when nginx is a proxy before Gunicorn](https://ctf.zeyu2001.com/2021/csaw-ctf-qualification-round-2021/gatekeeping)

# Tools for CTF
Here is a list to various useful tools for CTF competitions.

## Network

- [Wireshark](https://www.wireshark.org/) to analyze network connections

## Web

- [Postman](https://www.postman.com/) to make HTTP requests
- [OWASP ZAP](https://owasp.org/www-project-zap/) for analysing website security. Features include requests analysis and forgery, fuzzing, etc...
- [sqlmap](http://sqlmap.org/) for automatic SQL injection
- [webhook](https://webhook.site/) for receiving requests. See [Internal Support](DGHack2020/Web/InternalSupport.md) for an example of XSS attack.
- See [UpCredit](DGHack2020/Web/UpCredit.md) for an example of CSRF attack (without csrf token).

## Reverse engineering

- [Ghidra](https://ghidra-sre.org/) to decompile `c` code.
- [Java decompiler](http://www.javadecompilers.com/)
- [gdb](https://www.gnu.org/software/gdb/) a C debugger and its additional functionalities [gef](https://gef.readthedocs.io/en/master/)
- [OllyDbg](http://www.ollydbg.de/) a debugger for Windows programs
- [Android studio](https://developer.android.com/studio) to edit and analyse APK files and emulate APK
- [Apktool](https://ibotpeaches.github.io/Apktool/) for reversing APK files
- [angr](https://angr.io/) for symbolic execution. See [writeup](DarkCTF2020/Reversing/JACK.md).

## PWN

- [pwntools](http://docs.pwntools.com/en/stable/) a Python library for PWN
- [pwninit](https://github.com/io12/pwninit) for automatically starting pwn challenges.
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