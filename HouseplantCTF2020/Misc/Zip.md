# Zip-a-Dee-Doo-Dah

## Description

> I zipped the file a bit too many times it seems... and I may have added passwords to some of the zip files... eh, they should be pretty common passwords right?
> 
> Dev: William
> 
> Hint! A script will help you with this, please don't try do this manually...
> 
> Hint! All passwords should be in the SecLists/Passwords/xato-net-10-million-passwords-100.txt file, which you can get here : https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-100.txt
or alternatively, use "git clone https://github.com/danielmiessler/SecLists"

Attached 1819.gz

## Solution

I first begin to download the passlist, then try to decompress a few files manually. All decompressed files have names `n.extension` with `n` a decreasing integer, so I expect to uncompress 1819 files. Doing it manually is out of question of course. From the few 10 files I have decompressed, I have seen zip files, tar files and gz files. Some zip files also had a password.

So let's begin to automatize it, using this Python script. To construct it, I just implement some file, and when I reach a new type of file, I add the decompress function in the script. It happens that only the mentioned files above were enough.

I'm also using [JohntheRipper](https://www.openwall.com/john/) to crack passwords.

```python
import os
import zipfile
import subprocess
import tarfile
import gzip

file = "1819.gz"

def john_this():
    os.system("../../JohnTheRipper/run/zip2john {} > crack".format(file))
    p = subprocess.run(["../../JohnTheRipper/run/john", "--wordlist=pass.txt", "crack"], capture_output=True)
    return p.stdout.decode().split("\n")[1].split(" ")[0]


while True:
    if ".zip" in file:
        zf = zipfile.ZipFile(file)
        try:
            zf.testzip()
            file = zf.namelist()[0]
        except RuntimeError as e:
            if "encrypted" not in str(e):
                print(e)
                exit(1)
            pwd = john_this()
            file = zf.namelist()[0]
            zf.extract(pwd=pwd.encode(), member=file)
    elif ".tar" in file:
        tf = tarfile.open(file, mode="r")
        file = tf.next().name
        tf.extract(file)
    elif ".gz" in file:
        with gzip.GzipFile(file, mode="rb") as gf:
            input = gf.read()
        with open("next", "wb") as f:
            f.write(input)
        extension = os.popen("file next").read()
        if 'tar' in extension:
            os.rename("next", "next.tar")
            file = "next.tar"
        elif 'gzip' in extension:
            os.rename("next", "next.gz")
            file = "next.gz"
        elif 'Zip' in extension:
            os.rename("next", "next.zip")
            file = "next.zip"
        
        else:
            print(extension)
            break
```

I get a final text file with the flag.

Flag: `rtcp{z1pPeD_4_c0uPl3_t00_M4Ny_t1m3s_a1b8c687}`
