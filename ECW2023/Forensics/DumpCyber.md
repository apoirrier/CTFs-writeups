# DumpCyber

> I am lost inside this dump, to escape I think I need my key and IV?
>
> The challenge is available here.
>
> Note: the flag format for this challenge is flag{...}.

We are given a single file `task.raw`.

## Description

I don't really know what kind of file I have been given, so I try to get information:

```console
$ task.raw
task.raw: data

$ strings task.raw | less
```

The image cannot be mounted, and it contains a lot of references to Windows, so I'm assuming it is a dump of a Windows computer.

I verify this:

```console
$ volatility imageinfo -f task.raw
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
            AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
            AS Layer2 : FileAddressSpace (/home/apoirrier/ECW/dumpcyber/task.raw)
            PAE type : No PAE
                DTB : 0x187000L
                KDBG : 0xf800027fd0a0L
Number of Processors : 1
Image Type (Service Pack) : 1
    KPCR for CPU 0 : 0xfffff800027fed00L
    KUSER_SHARED_DATA : 0xfffff78000000000L
Image date and time : 2023-08-17 16:20:26 UTC+0000
Image local date and time : 2023-08-17 17:20:26 +0100
```

As expected, this is a Windows dump, so let's analyse it.

## Analysis

Here are the different commands that I run for analyzing the dump:

```console
$ volatility -f task.raw --profile=Win7SP1x64 consoles
**************************************************
ConsoleProcess: conhost.exe Pid: 568
Console: 0xff446200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: \\VBoxSvr\windows-windows\DumpIt.exe
Title: \\VBoxSvr\windows-windows\DumpIt.exe
AttachedProcess: DumpIt.exe Pid: 1320 Handle: 0x60
----
CommandHistory: 0x31ea00 Application: DumpIt.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
----
Screen 0x300e60 X:80 Y:300
Dump:
  DumpIt - v1.3.2.20110401 - One click memory memory dumper
  Copyright (c) 2007 - 2011, Matthieu Suiche <http://www.msuiche.net>
  Copyright (c) 2010 - 2011, MoonSols <http://www.moonsols.com>


    Address space size:        1073676288 bytes (   1023 Mb)
    Free space size:          50602553344 bytes (  48258 Mb)

    * Destination = \??\UNC\VBoxSvr\windows-windows\TASK-20230817-162019.raw

    --> Are you sure you want to continue? [y/n] y
    + Processing...
```

The console only contains the command that has been used to create the dump.

```console
$ volatility -f task.raw --profile=Win7SP1x64 psscan
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
0x000000000528b760 taskhost.exe       1264    496 0x00000000064b9000 2023-08-17 16:13:48 UTC+0000
0x0000000005c303a0 VBoxService.ex      708    496 0x0000000008e61000 2023-08-17 16:13:46 UTC+0000
0x00000000066b42b0 spoolsv.exe        1232    496 0x000000003cf13000 2023-08-17 16:13:47 UTC+0000
0x00000000070f1b30 svchost.exe        1288    496 0x0000000000685000 2023-08-17 16:13:48 UTC+0000
0x0000000007ad9910 dwm.exe            1148    924 0x00000000063ad000 2023-08-17 16:13:47 UTC+0000
0x00000000087e5350 svchost.exe        1020    496 0x0000000007bd0000 2023-08-17 16:13:47 UTC+0000
0x0000000009948210 WmiPrvSE.exe       1948    644 0x00000000315be000 2023-08-17 16:14:31 UTC+0000
0x000000000aea5b30 svchost.exe         764    496 0x000000000ae91000 2023-08-17 16:13:46 UTC+0000
0x000000000b39b750 svchost.exe         816    496 0x000000000a49e000 2023-08-17 16:13:46 UTC+0000
0x000000000cf31570 services.exe        496    420 0x0000000010da2000 2023-08-17 16:13:42 UTC+0000
0x000000000f046b30 lsass.exe           504    420 0x00000000124c2000 2023-08-17 16:13:42 UTC+0000
0x000000000f2477c0 lsm.exe             512    420 0x00000000124cb000 2023-08-17 16:13:42 UTC+0000
0x0000000010ff6060 svchost.exe         644    496 0x0000000029d1f000 2023-08-17 16:13:46 UTC+0000
0x00000000127c8740 winlogon.exe        524    412 0x000000000bf26000 2023-08-17 16:13:42 UTC+0000
0x000000001abcc060 csrss.exe           368    360 0x0000000019466000 2023-08-17 16:13:36 UTC+0000
0x000000001b3bc060 csrss.exe           432    412 0x0000000036820000 2023-08-17 16:13:42 UTC+0000
0x0000000028717b30 svchost.exe         924    496 0x00000000091aa000 2023-08-17 16:13:47 UTC+0000
0x000000002bd3a060 sppsvc.exe         1984    496 0x000000002d3e5000 2023-08-17 16:15:00 UTC+0000
0x00000000354e3060 svchost.exe        1364    496 0x000000002d2da000 2023-08-17 16:15:00 UTC+0000
0x00000000358ffb30 svchost.exe        1412    496 0x000000002d6f3000 2023-08-17 16:15:00 UTC+0000
0x0000000036f31b30 VBoxTray.exe       1428   1160 0x000000003bb26000 2023-08-17 16:13:48 UTC+0000
0x000000003a3a1b30 SearchIndexer.      944    496 0x0000000036fba000 2023-08-17 16:13:53 UTC+0000
0x000000003b228b30 svchost.exe         360    496 0x0000000008bbd000 2023-08-17 16:13:47 UTC+0000
0x000000003b65c510 explorer.exe       1160   1140 0x000000000007f000 2023-08-17 16:13:47 UTC+0000
0x000000003c3341c0 svchost.exe         972    496 0x00000000095b1000 2023-08-17 16:13:47 UTC+0000
0x000000003efdbb30 smss.exe            272      4 0x00000000265c7000 2023-08-17 16:13:27 UTC+0000
0x000000003fa00b30 WinRAR.exe         1280   1160 0x000000000f5db000 2023-08-17 16:20:22 UTC+0000
0x000000003fa25b30 WinRAR.exe         2144   1160 0x0000000030291000 2023-08-17 16:20:21 UTC+0000
0x000000003fa28060 SearchProtocol      376    944 0x0000000001ebe000 2023-08-17 16:20:14 UTC+0000
0x000000003fa32060 conhost.exe         568    432 0x000000000e8b2000 2023-08-17 16:20:19 UTC+0000
0x000000003faa5b30 WinRAR.exe         1280   1160 0x000000000f5db000 2023-08-17 16:20:22 UTC+0000
0x000000003facab30 WinRAR.exe         2144   1160 0x0000000030291000 2023-08-17 16:20:21 UTC+0000
0x000000003facd060 SearchProtocol      376    944 0x0000000001ebe000 2023-08-17 16:20:14 UTC+0000
0x000000003fad7060 conhost.exe         568    432 0x000000000e8b2000 2023-08-17 16:20:19 UTC+0000
0x000000003fb4ab30 WinRAR.exe         1280   1160 0x000000000f5db000 2023-08-17 16:20:22 UTC+0000
0x000000003fb6fb30 WinRAR.exe         2144   1160 0x0000000030291000 2023-08-17 16:20:21 UTC+0000
0x000000003fb72060 SearchProtocol      376    944 0x0000000001ebe000 2023-08-17 16:20:14 UTC+0000
0x000000003fb7c060 conhost.exe         568    432 0x000000000e8b2000 2023-08-17 16:20:19 UTC+0000
0x000000003fc2cb30 WinRAR.exe         2624   1160 0x000000002e179000 2023-08-17 16:20:25 UTC+0000
0x000000003fc7b100 audiodg.exe        1916    816 0x000000003a114000 2023-08-17 16:17:47 UTC+0000
0x000000003fc9c7f0 SearchFilterHo     2496    944 0x000000003acca000 2023-08-17 16:20:14 UTC+0000
0x000000003fd8fb30 notepad.exe        2880   1160 0x0000000019004000 2023-08-17 16:20:23 UTC+0000
0x000000003fde8b30 notepad.exe        2792   1160 0x000000002d557000 2023-08-17 16:20:24 UTC+0000
0x000000003fe6a7c0 wininit.exe         420    360 0x000000001436c000 2023-08-17 16:13:39 UTC+0000
0x000000003febeb30 DumpIt.exe         1320   1160 0x0000000010dad000 2023-08-17 16:20:19 UTC+0000
0x000000003ff37990 System                4      0 0x0000000000187000 2023-08-17 16:13:27 UTC+0000
```

Here we can see several processes that are of interest: the `notepad.exe` and `WinRAR.exe` processes.

Let's see which command spawned those processes:

```console
> volatility -f task.raw --profile=Win7SP1x64 cmdline -p 1280,2144,2880,2792
************************************************************************
WinRAR.exe pid:   2144
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\vboxuser\Desktop\file.txt.rar"
************************************************************************
WinRAR.exe pid:   1280
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\vboxuser\Desktop\generator.rar"
************************************************************************
notepad.exe pid:   2880
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\vboxuser\Desktop\deesktop.ini
************************************************************************
notepad.exe pid:   2792
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\vboxuser\Desktop\dessktop.ini
```

## Extracting files

This is interesting, we see four files that can be of interest.

The description says that the flag is encrypted and that we need an IV and a key, so I'm guessing that they are the `.ini` files and the flag is stored in `file.txt.rar`.

Let's extract those files:

```console
$ volatility -f task.raw --profile=Win7SP1x64 filescan | grep Desktop
0x000000003fabd070     16      0 RW---- \Device\HarddiskVolume1\Users\vboxuser\Desktop\file.txt.rar
0x000000003fcd2430     16      0 RW---- \Device\HarddiskVolume1\Users\vboxuser\Desktop\dessktop.ini
0x000000003fd737b0     16      0 RW---- \Device\HarddiskVolume1\Users\vboxuser\Desktop\deesktop.ini

$ volatility -f task.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fabd070 -D . -n
$ volatility -f task.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fcd2430 -D . -n
$ volatility -f task.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fd737b0 -D . -n

$ unrar x file.None.0xfffffa800487b860.file.txt.rar.dat
$ unrar x file.None.0xfffffa8000c7d9e0.dessktop.ini.dat
$ unrar x file.None.0xfffffa8003e37b10.deesktop.ini.dat
```

## Getting the flag

We can finally get the flag with the following Python script:

```python
from Crypto.Cipher import AES
with open("deesktop.ini", "rb") as f:
    deesktop = f.read()
with open("dessktop.ini", "rb") as f:
    dessktop = f.read()
with open("file.txt.enc", "rb") as f:
    ctxt = f.read()
print(AES.new(key=deesktop, mode=AES.MODE_CBC, iv=dessktop).decrypt(ctxt))
print(AES.new(key=dessktop, mode=AES.MODE_CBC, iv=deesktop).decrypt(ctxt))
```

Flag: `flag{82a30fadcfc07d634fbed1bffe4a2aa1}`