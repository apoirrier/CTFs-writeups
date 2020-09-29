# Wolfie's Password

> We have found another device which is password protected but he uses same password everywhere find his password
>
> Note: Use the same file provided in Wolfie's Contacts
>
> Flag Format: darkCTF{password}

The file is an E01 device.

## Description

I mount the device using [OSFMount](https://www.osforensics.com/tools/mount-disk-images.html) and explore the different folders. On one of them (`not important files`) I stumble across an encrypted rar file.

I guess the password from the rar file will be the password we are looking for, so I will try to crack it using [John the ripper](https://www.openwall.com/john/).

## Solution

Using the following commands gives me the password:

``` bash
rar2john readme.rar > readme.txt
john --wordlist=rockyou.txt readme.txt
```

Then I put the password inside `darkCTF{}` to get the flag.

Flag: `darkCTF{easypeasy}`