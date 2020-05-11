# My huge file

> I have a very big file for you. I hid a present inside.
> Classic tools wont be useful here.

## Description

In this challenge we had to connect to a remote machine trought SSH and find information in a huge file.

Upon connecting my first reflex was:
```
ls -al --human-readable
```
And we realise that the file is about 16 Tb.

## Solution

### Investigation

16 Tb is big for a file, and we can't expect every team to parse that much information in such a short time, without being a news: [record with 100 Tb for 23 minutes link](https://www.wired.com/2014/10/startup-crunches-100-terabytes-data-record-23-minutes/)

```
df --human-readable
```

Tells us that the the machine doesn't have that much memory to begin with.


A quick Google search taught me about sparse files: [wiki](https://wiki.archlinux.org/index.php/sparse_file). The data was only allocated when we attempted to read into it, and we would only get zeros.

### Getting the Flag

Fortunately when reading a file in Python 3.3 we can ask to jump to the next allocated chunk:

```python
os.lseek(file_descriptor, pos, os.SEEK_SET | os.SEEK_DATA)
```

My algorithm was simply to jump in the file with *lseek* read the next few bytes. then using file.tell(). Get the current position, to make another jump with lseek.

In the end, the bytes of the flag were scattered across the file.

`Flag:shkCTF{sp4rs3_f1l3s_4r3_c001_6cf61f47f6273dfa225ee3366eacb8eb}`
