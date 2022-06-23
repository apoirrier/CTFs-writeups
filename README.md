# CTFs-writeups
Writeups for various CTFs competitions.

On this page you can find links to writeups for the following categories:
- [Blockchain](#blockchain)
- [Cryptography](#cryptography)
- [Forensics](#forensics)
- [Cheating in games](#games)
- [Miscellaneous](#misc)
- [OSINT](#osint)
- [Pwn](#pwn)
- [Brute-forcing passwords](#password-cracking)
- [Quantum cryptography](#quantum)
- [Reverse engineering](#reversing)
- [Web](#web)

You can also find a [list of useful CTF tools](#tools-for-ctf).

# Example of writeups

## Blockchain

### Eth

- [Blockchain transactions are public (ETH)](SharkyCTF2020/Blockchain/Guessing.md)
- [Reentrancy exploit](SharkyCTF2020/Blockchain/Multipass.md)
- [Set up of environment, underflow and reentrancy](404CTF2022/Web3/GuerreContrats.md)

### Bitcoin

- [Bitcoin transaction vulnerability](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Duplicacy%20Within#duplicacy-within)

## Cryptography

### Easy crypto

- [OTP reuse](UTCTF2020/One%20True%20Problem.md)
- [Morse from audio](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
- [Enigma](BrigitteFriang/Crypte.md)
- [Enigma avec IC](404CTF2022/Crypto/Enigma.md)
- [Lot of guessy ciphertexts without knowledge of cipher](https://www.youtube.com/watch?v=9Q5Q1Nn5Vss)
- [Hill cipher](https://github.com/t3rmin0x/CTF-Writeups/tree/master/DarkCTF/Crypto/Embrace%20the%20Climb#embrace-the-climb-)

### General crypto

- [Double DES](PicoCTF/Crypto/DoubleDes.md)

### AES

- [Malleability of the first block in AES-CBC](AwesomeCTF2020/Crypto/Access.md)
- [Padding oracle attack on AES-CBC](SharkyCTF2020/Crypto/Backflip.md)
- [IV recovery with partially known plaintext, ciphertext and key in AES-CBC](TMUCTF2021/Crypto/435!.md)
- [Exploiting predictable IV in AES-CBC](DGHack2021/Crypto/CBC.md)
- [Differential Power Analysis on first round of AES](404CTF2022/Crypto/Kocher.md)

### RSA
- [RSA with ciphertext super small](CSAWQual2021/crypto/GottaDecryptThemAll.md)
- [Attacks on RSA: Wiener, sexy primes, LSB oracle, partial private key leaked](CSAWQual2021/crypto/RSAPopQuiz.md)
- [Multi-primes RSA](TMUCTF2021/Crypto/CommonFactor.md)
- [Fixed point in RSA](404CTF2022/Crypto/UnPointCestTout.md)
- [RSA full oracle](404CTF2022/Crypto/SimpleOracle.md)

### Hashes
- [Hash length extension attack](TAMUCTF2020/Crypto/Eternal%20Game.md)
- [Find a preimage for the Python hash function](FCSC2022/Crypto/Hashish.md)

### Cryptography in subgroups of Z or Z*

- [DLP, order of N has small factors](BrigitteFriang/LeDiscretNapier.md)
- [ElGamal signature scheme without hash existential forgery](CSAWQual2021/crypto/Forgery.md)
- [Break DH key exchange with Pohlig-Hellman attack for DLP](TJCTF2020/Cryptography/DifficultDecryption.md)
- [Oracle for finding secret exponent](404CTF2022/Crypto/DegatsCollateraux.md)

### Elliptic curves

- [CRT on EC points](BrigitteFriang/VXElliptique.md)

### Bad randomness
- [Retrieve state of java.util.Random PRNG](SharkyCTF2020/Crypto/Casino.md)
- [Solve system of integer inequalities - java.util.Random calls](https://gist.github.com/myrdyr/c1b77f1cbd8e2acb117e74c7831ef876)

### Esoteric

- [Custom VHDL cipher on FPGA](BrigitteFriang/EvilCipher.md)
- [Hardware AES key, CRT, Galois fields](BrigitteFriang/crypto.md)
- [Encryption oracle with plaintext compressed](PicoCTF/Crypto/CompressAndAttack.md)
- [Example in RUST](DGHack2021/Crypto/Mascarade.md)


## Forensics

### Images

- [Broken JPEG header](AwesomeCTF2020/Forensics/CheapFacades.md)
- [Broken PNG image](AwesomeCTF2020/Forensics/Dimensionless.md)
- [Broken BMP header](PicoCTF/Forensics/tunn3l_v1s10n.md)
- [Flag hidden in bit plane of image](Dawg2020/Forensics/UMBCShield.md)
- [Image manipulation with PIL](TJCTF2020/Forensics/Unimportant.md)
- [Hidden flag in PNG (zsteg)](https://github.com/xnomas/PicoCTF-2021-Writeups/tree/main/Milkslap)
- [Hidden flag in scanline filter of PNG](404CTF2022/Stegano/PNG.md)
- [Code128](404CTF2022/Programmation/128code128.md)

### Audio

- [binwalk and flag hidden in spectrogram of audio file](AwesomeCTF2020/Forensics/MonsterIssue.md)
- [UART](BrigitteFriang/ASCII_UART.md)
- [SSTV](UTCTF2020/1%20Frame%20per%20Minute.md)
- [Some signal analysis (Winlink)](https://github.com/tttttx2/CTF_Writeups/blob/main/PBCTF-2021/Is_that_your_packet.md)
- [WAV file is an oscilloscope input](404CTF2022/Stegano/Stereographie.md)

### PDF

- [PDF recover streams and CMap](404CTF2022/Forensics/AgentCompromis.md#partie-3)

### Network files

- [Scapy to read pcap](CSAWQual2021/ics/APainInTheBacnet.md)
- [Extract TFTP files](PicoCTF/Forensics/TrivialFlagTransferProtocol.md)

### Dump files

- [Android dump position history](BrigitteFriang/Ocean.md)
- [Arduino](https://ctftime.org/writeup/21344)
- [Analyse dump file with volatility](https://github.com/l4u23n7p/dghack-2020/tree/main/bwing)
- [Windows recurring task](DGHack2021/Inforensique/iDisk.md)
- [Repair RAID files](404CTF2022/Forensics/RAID.md)

### Signal in a wire

- [Keypad sniffer](BrigitteFriang/KeypadSniffer.md)
- [EEPROM Arduino eletrical circuit VCD file](FCSC2022/Hardware/I2CYouToo.md)
- [8b10b](404CTF2022/Misc/8vers10.md)
- [Non Return to Zero Inverted](404CTF2022/Misc/Cable.md)

### Esoteric

- [Polyglotte files](BrigitteFriang/Polyglotte.md)
- [Hidden flag in RSA parameter](BrigitteFriang/Stranger.md)
- [Detect falsified data with Benford's law](Dawg2020/Forensics/benford_law_firm.md)
- [Automating decompression with password cracking](HouseplantCTF2020/Misc/Zip.md)
- [Read sparse files](SharkyCTF2020/Misc/My-huge-file.md)
- [Color hex values](TJCTF2020/Forensics/Hexillogy.md)
- [Sound keylogger](PBCTF2021/Misc/GhostWriter.md)
- [Elastic search](DGHack2021/Détection/MEGACORP.md)


## Games

- [Cheat in WASM games](https://c-anirudh.github.io/posts/tjctf-gamerw-writeup/)
- [Modify client of Godot scripts MMORPG game to cheat](https://mahaloz.re/tasteless-21-tasteless-shores/)

## Misc
- [Bypass float comparison in Python](AwesomeCTF2020/Misc/Teleport.md)
- [Read QR code with Python](HouseplantCTF2020/Web/QRGenerator.md)
- [Python bytecode](https://ypl.coffee/ractf-2020-puffer-overflow/)
- [Create Signal with a given frequency](FCSC2022/Hardware/MommyMorse.md)
- [Homoglyphes](404CTF2022/Programmation/DonneesCorrompues.md)

## OSINT

- [Github older commit](AUCTF2020/OSINT/WhoMadeMe.md)
- [Old version of pip library](AwesomeCTF2020/Misc/Spentalkux.md)
- [Find password of an employee in social network](Dawg2020/Forensics/ImpossiblePenTest.md)
- [Old version of website](404CTF2022/OSINT/Collaborateur.md)

## PWN

### Buffer overflow

- [Simple buffer overflow](AUCTF2020/PWN/ThanksgivingDinner.md)
- [32 bits ROP chain buffer overflow](AUCTF2020/PWN/HouseofMadness.md)
- [NX disabled](TJCTF2020/Pwn/ElPrimo.md)
- [Write shellcodes with restrictions](PicoCTF/Pwn/filtered-shellcode.md)
- [Get a shell using dup2 and execv with ROP](DGHack2021/Exploit/SMTP.md)

### Simple format string

- [Format string vulnerability to bypass canary and PIE for buffer overflow](AwesomeCTF2020/PWN/FinchesPIE.md)
- [GOT override with format string vulnerability (no PIE)](AwesomeCTF2020/PWN/NRA.md)

### ret2lib

- [32 bit ret2lib with buffer overflow](DarkCTF2020/Pwn/newPaX.md)
- [64 bit ret2lib with buffer overflow](DarkCTF2020/Pwn/roprop.md)
- [ret2lib with ASLR and PIE with only format string vulnerabilities](https://github.com/KrauseBerg/CTF-writeups-1/blob/patch-1/CSAW%602021/procrastination.py)

### File Struct Oriented Programming

- [FSOP par heap overflow](https://remyoudompheng.github.io/ctf/404ctf/chgarchi2.html)
- [Guide FSOP](https://faraz.faith/2020-10-13-FSOP-lazynote/)
- [Autre guide](https://gsec.hitb.org/materials/sg2018/D1%20-%20FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf)

### Break PRNG

- [Guess randomness of rand with srand(time)](CSAWQual2021/pwn/haySTACK.md)

### Privilege escalation

- [Privilege escalation on Linux machine, exit rbash](BrigitteFriang/AloneMusk.md)
- [Open tty shell to exploit less for privilege escalation](DGHack2021/Exploit/SMTP.md)
- [Read file in restricted bash](404CTF2022/Misc/Suspicieux.md#partie-2)

### Heap exploitation

- [Reallocate chosen freed block from tcache](https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Cache_Me_Outside.md)

### Python

- [Python 2 input](https://intx0x80.blogspot.com/2017/05/python-input-vulnerability_25.html)
- [Python string equal bypass before int](https://www.compart.com/en/unicode/search?q=zero#characters)

### Java

- [log4shell](https://github.com/pasterp/CTF_WriteUps/blob/main/2022/404CTF/misc/joutes_arches_vallees_arbaletes.md)

## Password cracking

- [Simple john](AUCTF2020/Password_Cracking/Crackme.md)
- [Salted hash](AUCTF2020/Password_Cracking/Salty.md)
- [Custom List](AUCTF2020/Password_Cracking/Mental.md)
- [KDBX](AUCTF2020/Password_Cracking/Manager.md)
- [ZIP](AUCTF2020/Password_Cracking/Zippy.md)
- [KDBX with key file](404CTF2022/Forensics/Ransomware3.md)
- [Similar password](404CTF2022/Forensics/Ransomware3.md)

## Quantum

- [Quantum key distribution](https://ctf.zeyu2001.com/2021/csaw-ctf-qualification-round-2021/save-the-tristate)

## Reversing

### Java and Android

- [Java decompiler](AUCTF2020/Reversing/MrGameAndWatch.md)

### Python

- [Python bytecode reverse](404CTF2022/Reverse/Tour.md#partie-2)
- [PYC reverse](404CTF2022/Reverse/MaJ.md#pas-de-maj)

### Assembly

- [Assembly reversing](AUCTF2020/Reversing/PlainJane.md)
- [ARMv8 assembly reversing](PicoCTF/Reversing/ARMssembly0.md)
- [Portable executable compiled with Cosmopolitain](https://rainbowpigeon.me/posts/pbctf-2021/#cosmo)
- [In-memory loading technique](https://www.aperikube.fr/docs/dghack_2020/dharma_exe/)
- [vTable hook](https://www.aperikube.fr/docs/dghack_2021/introspection/)

### Micro-controllers and circuits

- [Arduino Intel HEX format](https://www.aperikube.fr/docs/dghack_2020/strange_thing/)
- [Logic gates](404CTF2022/Reverse/Portes.md)

### Other static analysis

- [Extract data from ELF](DGHack2021/Détection/YARA.md)


### Dynamic analysis

- [Use angr to crack password](DarkCTF2020/Reversing/JACK.md)
- [Use gdb to debug child after fork](DGHack2021/Exploit/SMTP.md)
- [Reverse OS launched with qemu](DGHack2021/Reverse/OSS117.md)
- [Example of reversing using OllyDbg and Ghidra](FCSC2022/Reverse/IconicLicense.md)
- [Brute force password on Android app](404CTF2022/Reverse/FridaMe.md)


## Web

### Language vulnerabilities

- [PHP injection with eval used](AUCTF2020/Web/quick_maths.md)
- [Exploit javascript equality check to bypass hash collision](AwesomeCTF2020/Web/C0llide.md)
- [PHP deserialize](https://github.com/skyf0l/CTF/blob/master/PicoCTF2021/README.md#super-serial)
- [.Net core C# getters and setters exploits](https://dashboard.malice.fr/uploads/dghack/writeups/WriteUp_FlightControl.pdf)
- 

### SQL attacks

- [Blind SQLi, path transversal](AwesomeCTF2020/Web/Quarantine.md)
- [Another blind SQLi](TAMUCTF2020/Web/Password_extraction.md)
- [SQL union attack, weak new password procedure](BrigitteFriang/web.md)
- [Blind SQLi: guessing tables and finding flag](https://nicolasb.fr/blog/writeup-dghack-stickitup/)
- [MySQL UNION attack with some filters](404CTF2022/Web/Braquage.md)

### Session tokens
- [disable JWT signing](AwesomeCTF2020/Web/Quarantine.md)
- [JWT with RS256 and weak RSA key](TMUCTF2021/Web/TheDevilNeverSleeps.md)
- [Flask cookies](PicoCTF/Web/MostCookies.md)
- [exploit redirect parameter in OAuth to steal access token](https://nicolasb.fr/blog/writeup-dghack-job-board/)

### RCE with SSTI

- [Jinja2 SSTI](CSAWQual2021/web/ninja.md)

### XSS

- [Reflected XSS](DGHack2020/Web/InternalSupport.md)
- [Reflected XSS with older version of browser (SameSite=None)](DGHack2020/Web/UpCredit.md)
- [Bypass WAF for reflected XSS](TJCTF2020/Web/AdminSecrets.md)
- [Use javascript: URL scheme to provoke XSS](https://bawolff.blogspot.com/2021/10/write-up-pbctf-2021-tbdxss.html)

### XXE

- [Custom Wordpress vulnerability](https://mizu.re/post/xml-is-love-is-life)

### Proxy stuff

- [Bypass nginx deny-all when nginx is a proxy before Gunicorn](https://ctf.zeyu2001.com/2021/csaw-ctf-qualification-round-2021/gatekeeping)
- [Exploit SSRF to access intranet](https://www.notion.so/Write-Up-Op-ration-Brigitte-Friand-ChatBot-268b8b65b8c04c6184f5d8109767fe37)

### WASM

- [Disassemble WASM](PicoCTF/Web/SomeAssemblyRequired1.md)

### CVE

- [Apache CVE example](https://nicolasb.fr/blog/writeup-dghack-walters-blog/)
- [Gitlab CVE example](https://github.com/l4u23n7p/dghack-2020/tree/main/gitbad)
- [Laravel (PHP) LFI leading to RCE due to CVE in dependency](https://writeup.wh1t3r0s3.xyz/web/instakilogram-200-points)


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
- [flask-unsign](https://pypi.org/project/flask-unsign/) for decoding, cracking and forging Flask cookies.

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
- [shellcodes](http://shell-storm.org/shellcode/)

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
- [zsteg](https://github.com/zed-0xff/zsteg) for images

## Forensics
- [Autopsy](https://www.autopsy.com/) for device analysis
- [Acoustic keylogger](https://github.com/shoyo/acoustic-keylogger)
- [Sigidwiki](https://www.sigidwiki.com/wiki/Signal_Identification_Guide) a signal identification guide
- [volatility](https://github.com/volatilityfoundation/volatility)

## Cryptography

- https://www.dcode.fr/en It knows a lot of common cypher methods and does automatic uncyphering
- [hlextend](https://github.com/stephenbradshaw/hlextend) a Python library for length extension attacks on Merkle-Damgård hash functions
- Factorize big integers with http://factordb.com/
- Reverse seeds given inequality constraints for Java random: [JavaRandomReverser](https://github.com/mjtb49/LattiCG)
- [Solve integer inequalities with CSP](https://github.com/rkm0959/Inequality_Solving_with_CVP)

## Password cracking

- [JohntheRipper](https://www.openwall.com/john/)

## OSINT

- [Sherlock](https://github.com/sherlock-project/sherlock) to scrap information on social media
- [Wayback Machine](https://web.archive.org/)
- [Webpage archive](https://archive.today/)

## Misc

- If you know the format of the flag, you can use `flag_converter.py` to quickly have the most common encoding of the flag, so you know what to look for during the competition ;)
- https://www.asciitohex.com/  For quick conversion between ASCII, decimal, base64, binary, hexadecimal and URL
- https://gchq.github.io/CyberChef/ Same as asciitohex but more complete, with magic wand.
- https://upload.wikimedia.org/wikipedia/commons/d/dd/ASCII-Table.svg: An Ascci to decimal, hexadecimal, binary and octal table
- Deal with images in Python using [PIL](https://pillow.readthedocs.io/en/stable/). See [example writeup](DarkCTF2020/Misc/QuickFix.md)
- Cheat in WASM games: [Cetus](https://github.com/Qwokka/Cetus)
- [Decompiler for GDScripts](https://github.com/bruvzg/gdsdecomp)
