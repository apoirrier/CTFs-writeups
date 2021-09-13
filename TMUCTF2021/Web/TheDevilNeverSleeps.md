# The Devil Never Sleeps

> If you put the devil to sleep, you will get the flag successfully. Unfortunately, the devil never sleeps. But what if you use some sleeping pills?
>
> http://194.5.207.57:8080

## Description

If we go to the website, we are greeted with the following:
> To get sleeping pills, navigate to /sleepingpill. To get the flag, navigate to /flag.

Going to /sleepingpill gives us a pill key (a public key) and a sleeping pill (a JWT token):
```
{"pill_key":"-----BEGIN PUBLIC KEY-----\nMIGsMA0GCSqGSIb3DQEBAQUAA4GaADCBlgKBjgD/////////////////////////\n/////////////////////////////////////////////////////////////3//\n///////////+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwEAAQ==\n-----END PUBLIC KEY-----","sleeping_pill":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYzMTU0NzM5MiwianRpIjoiYjQyNTk1MzUtMzgyYS00ZjhiLThmMTYtYTg2OTM2MjUwODJlIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmlsIiwibmJmIjoxNjMxNTQ3MzkyLCJleHAiOjE2MzE1NDgyOTIsInNsZWVwIjoiZmFsc2UiLCJkYW5nZXIiOiJ0cnVlIn0.Cnh9dm-Qe16FwTuR9E11Y7yOFSRjHOiGBcF6-Vt0LHph2FQWFkxlluF00052p4SEZOdq2w46nMLmLqKVR9D5GsfSiVu8L_PkBVjjP9xpI9dxZ4sN0mts_AdW_q3Ceg2Hb_cpvGVhK_hCp0WoQPaYPFsWqep-toR5elifXlHuMh-Yl3ijATN5EKFMOaPx"}
```

By going to /flag we see that there is a missing Pill Header, so we add a Pill header with our token using Postman. Another error message tells us we need to prepend Bearer, so let's do that.

Of course we don't get the flag back.

![](../images/devil.png)

## Solution

We need to understand what the token does. Let's decode it with [jwt.io](https://jwt.io/).

We learn the verification algorithm is RS256 and the payload is the following:

```python
{
  "fresh": false,
  "iat": 1631547392,
  "jti": "b4259535-382a-4f8b-8f16-a8693625082e",
  "type": "access",
  "sub": "devil",
  "nbf": 1631547392,
  "exp": 1631548292,
  "sleep": "false",
  "danger": "true"
}
```

We need to modify this payload. First we want to crack the RSA key. To that end, I open the RSA key given:

```python
from Crypto.PublicKey import RSA

f = open('pill_key.pub','r')
key = RSA.import_key(f.read())
print(key.n)
print(key.e)
```

Then I give the modulus to [factordb](http://factordb.com/) and I get the factorization immediately.
Thus I can construct the private key:

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

f = open('pill_key.pub','r')
key = RSA.import_key(f.read())

p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
q = 531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127

phi = (p-1)*(q-1)
d = inverse(key.e, phi)

priv_key = RSA.construct((key.n, key.e, d))
with open('pill_key.priv', 'wb') as g:
    g.write(priv_key.export_key())
```

Then I use [jwttool](https://github.com/ticarpi/jwt_tool) to modify my JWT:

```bash
python3 jwt_tool/jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYzMTU0NzM5MiwianRpIjoiYjQyNTk1MzUtMzgyYS00ZjhiLThmMTYtYTg2OTM2MjUwODJlIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmlsIiwibmJmIjoxNjMxNTQ3MzkyLCJleHAiOjE2MzE1NDgyOTIsInNsZWVwIjoiZmFsc2UiLCJkYW5nZXIiOiJ0cnVlIn0.Cnh9dm-Qe16FwTuR9E11Y7yOFSRjHOiGBcF6-Vt0LHph2FQWFkxlluF00052p4SEZOdq2w46nMLmLqKVR9D5GsfSiVu8L_PkBVjjP9xpI9dxZ4sN0mts_AdW_q3Ceg2Hb_cpvGVhK_hCp0WoQPaYPFsWqep-toR5elifXlHuMh-Yl3ijATN5EKFMOaPx -pk pill_key.pub -pr pill_key.priv -T -S rs256
```

I leave the algorithm part as it is, change `sleep` to `true`, update earliest timestamp to current time (keeping offsets) and inputs the returned token on Postman.

Flag: `TMUCTF{0h_51nn3rm4n_Wh3r3_Y0u_60nn4_Run_70?}`