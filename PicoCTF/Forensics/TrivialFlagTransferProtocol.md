# Trivial Flag Transfer Protocol

> Figure out how they moved the flag.

A pcap file is provided.

## Solution

We open the pcap with Wireshark and see this is a [TFTP](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol#:~:text=Trivial%20File%20Transfer%20Protocol%20(TFTP,from%20a%20local%20area%20network.) transmission.

There are several files exchanged, which we can export with `File -> Export Objects -> TFTP`.

Once exported we see several files: 3 images, `instructions.txt`, `plan` and `program.deb`.

We begin by reading `instructions.txt`:
```
GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA
```
We give it to CyberChef, and guess this is a ROT13 cipher. So here is the translation:
```
TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN
```

Great so next step is to check the plan, which is also a ROT13 text.
```
IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
```

So let's install the program with `dpkg i program.deb`. It is actually steghide, but an older version with broken dependencies, so I preferred to use the [web version](https://futureboy.us/stegano/decinput.html).

I know the password is `DUEDILIGENCE` and try each one of the image one by one.

Flag: `picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}`
