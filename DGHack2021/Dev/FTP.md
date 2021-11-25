# Secure FTP over UDP

> Votre société a acheté un nouveau logiciel de serveur FTP. Celui-ci est un peu spécial et il n'existe pas de client pour Linux !
>
> > À l'aide de la documentation fournie ci-dessous, implémentez un client allant jusqu'à l'établissement d'une session.
>
> udp://secure-ftp.dghack.fr:4445/

## Description

We get a description of a protocol to read files on a distant server working on UDP.

We need to implement a client for this protocol.

For this writeup I will show my code little by little and comment it.

### The Packet class

I have defined a generic class for packets.
It defines the different IDs for packet types and is defined by a content `contenu` and a type.

It has a method to build itself (in form of a byte array) which computes the CRC and forms the packet.

It also has a static method that does the reverse: taking bytes and parse it as packets.

The class also has helper functions to serialize and extract strings, extract parameters from bytes and perform AES operations.

```python
class WrongCRC(Exception):
    pass

class Packet:
    ConnectMessage = 1921
    ConnectReply = 4875
    RSAKeyMessage = 78
    RSAKeyReply = 98
    SessionKeyMessage = 1337
    SessionKeyReply = 1338
    AuthMessage = 4444
    AuthReply = 6789
    GetFilesMessage = 45
    GetFilesReply = 46
    GetFileMessage = 666
    GetFileReply = 7331
    def __init__(self, type, contenu):
        self.contenu = contenu
        self.id = type

    def __str__(self) -> str:
        return "Packet with id {} and content:\n{}".format(self.id, self.contenu)

    def crc32(data):
        return long_to_bytes(zlib.crc32(data) & 0xffffffff)

    def build(self):
        taille = long_to_bytes(len(self.contenu))
        entete = self.id << 1
        entete |= (len(taille) // 2)
        entete = entete << 1
        entete |= (len(taille) % 2)
        entete = long_to_bytes(entete)
        entete = entete.rjust(2, b"\x00")

        packet = entete + taille + self.contenu
        return packet + Packet.crc32(packet)

    def serialize_string(s):
        length = long_to_bytes(len(s)).rjust(2, b"\x00")
        return length + s

    def extract_string(s):
        length = bytes_to_long(s[:2])
        return s[2:2+length]

    def parse_parameters(s):
        i = 0
        params = []
        while i < len(s):
            params.append(Packet.extract_string(s[i:]))
            i += (2 + len(params[-1]))
        return params

    def extract_array(a):
        return a[2:].split(b"\x00")

    def parse(packet):
        if Packet.crc32(packet[:len(packet)-4]) != packet[len(packet)-4:]:
            raise WrongCRC
        entete = bytes_to_long(packet[:2])
        id = entete >> 2
        len_taille = entete & 3
        contenu = packet[2+len_taille:len(packet)-4]
        if id == Packet.ConnectReply:
            return ConnectReply(contenu)
        elif id == Packet.RSAKeyReply:
            return RSAKeyReply(contenu)
        elif id == Packet.AuthReply:
            return AuthReply(contenu)
        return Packet(id, contenu)

    def encrypt(AESKey, m):
        iv = os.urandom(16)
        cipher_aes = AES.new(AESKey, AES.MODE_CBC, iv)
        ptxt = pad(iv + m, AES.block_size)
        ctxt = cipher_aes.encrypt(ptxt)
        return base64.b64encode(ctxt)

    def decrypt(AESKey, ctxt):
        cipher_aes = AES.new(AESKey, AES.MODE_CBC)
        ctxt = base64.b64decode(ctxt)
        ptxt = cipher_aes.decrypt(ctxt)
        return unpad(ptxt, AES.block_size)[16:]
```

### Specialized packets

The following classes extend the Packet class to match specific types of packets.

```python
class ConnectMessage(Packet):
    def __init__(self):
        data = Packet.serialize_string(b"CONNECT")
        super().__init__(Packet.ConnectMessage, data)

class ConnectReply(Packet):
    def __init__(self, contenu):
        super().__init__(Packet.ConnectReply, contenu)
        params = Packet.parse_parameters(contenu)
        self.sessionID = params[0]
        self.flag = params[1]

    def __str__(self) -> str:
        return "ConnectReply:\n\tsessionID: {}\n\tflag: {}\n".format(self.sessionID, self.flag)

class RSAKeyMessage(Packet):
    def __init__(self, sessionID):
        data = Packet.serialize_string(sessionID)
        super().__init__(Packet.RSAKeyMessage, data)

class RSAKeyReply(Packet):
    xorkey = b"ThisIsNotSoSecretPleaseChangeIt"

    def __init__(self, contenu):
        super().__init__(Packet.ConnectReply, contenu)
        params = Packet.parse_parameters(contenu)
        self.RSAKey = RSAKeyReply.decryptKey(params[0])

    def __str__(self) -> str:
        return "RSAKeyReply:\n\tRSAKey: {}\n".format(self.RSAKey)

    def decryptKey(key):
        key = base64.b64decode(key)
        xorkey = b""
        while len(xorkey) < len(key):
            xorkey += RSAKeyReply.xorkey
        xorkey = xorkey[:len(key)]
        return strxor(key, xorkey)

class SessionKeyMessage(Packet):
    def __init__(self, sessionID, RSAKey, AESKey):
        data = Packet.serialize_string(sessionID)
        data += Packet.serialize_string(SessionKeyMessage.encodeKey(RSAKey, AESKey))
        super().__init__(Packet.SessionKeyMessage, data)

    def encodeKey(RSAKey, AESKey):
        RSAKey = RSA.import_key(RSAKey)
        rsa_cipher = PKCS1_v1_5.new(RSAKey)
        enc_session_key = rsa_cipher.encrypt(AESKey)
        return base64.b64encode(enc_session_key)

class SessionKeyReply(Packet):
    def __init__(self, contenu, AESKey):
        super().__init__(Packet.SessionKeyReply, contenu)
        params = Packet.parse_parameters(contenu)
        self.salt = Packet.decrypt(AESKey, params[0])

    def __str__(self) -> str:
        return "SessionKeyReply:\n\salt: {}\n".format(self.salt)

class AuthMessage(Packet):
    def __init__(self, AESKey, sessionID, salt, identifiant, motDePasse):
        data = Packet.serialize_string(sessionID)
        data += Packet.serialize_string(Packet.encrypt(AESKey, salt))
        data += Packet.serialize_string(Packet.encrypt(AESKey, identifiant))
        data += Packet.serialize_string(Packet.encrypt(AESKey, motDePasse))
        super().__init__(Packet.AuthMessage, data)

class AuthReply(Packet):
    def __init__(self, contenu):
        super().__init__(Packet.AuthReply, contenu)
        params = Packet.parse_parameters(contenu)
        self.status = params[0]
        self.flag = params[1]

    def __str__(self) -> str:
        return "AuthReply:\n\tstatus: {}\n\tflag: {}\n".format(self.status, self.flag)

class GetFilesMessage(Packet):
    def __init__(self, AESKey, sessionID, path):
        data = Packet.serialize_string(sessionID)
        data += Packet.serialize_string(Packet.encrypt(AESKey, path))
        super().__init__(Packet.GetFilesMessage, data)

class GetFilesReply(Packet):
    def __init__(self, AESKey, contenu):
        super().__init__(Packet.GetFilesReply, contenu)
        tab = Packet.extract_array(contenu)
        self.files = [Packet.decrypt(AESKey, s) for s in tab]

    def __str__(self) -> str:
        s = "GetFilesReply:\n\tfiles:\n"
        for f in self.files:
            s += "\t\t- {}\n".format(f)
        return s


class GetFileMessage(Packet):
    def __init__(self, AESKey, sessionID, path):
        data = Packet.serialize_string(sessionID)
        data += Packet.serialize_string(Packet.encrypt(AESKey, path))
        super().__init__(Packet.GetFileMessage, data)

class GetFileReply(Packet):
    def __init__(self, AESKey, contenu):
        super().__init__(Packet.GetFileReply, contenu)
        s = Packet.extract_string(contenu)
        self.file = Packet.decrypt(AESKey, s)

    def __str__(self) -> str:
        return "GetFilesReply:\n\tfile_content: {}\n".format(self.file)
```

It basically follows the documentation.

### Protocol

Finally, the `session.py` file follows the protocol.
It connects to the UDP channel and defines the `send_and_recv` function, which takes as input a packet, sends it (with retry if something bad happens) and retrieves the output.

```python
from packet import *
import socket
import os

SERVER = ("secure-ftp.dghack.fr", 4445)
MESSAGE_SIZE = 2048
IDENTIFIANT = b"GUEST_USER"
MOT_DE_PASSE = b"GUEST_PASSWORD"
DIRECTORY = b"/opt/dga2021"
FILE = b"/opt/dga2021/flag"

UDPSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPSocket.settimeout(2)

def send_and_recv(packet, retries=5):
    if retries == 0:
        print("Too many retries")
        exit(1)
    try:
        UDPSocket.sendto(packet.build(), SERVER)
        recvd = UDPSocket.recvfrom(MESSAGE_SIZE)
        return Packet.parse(recvd[0])
    except Exception:
        return send_and_recv(packet, retries-1)


# Session
reply = send_and_recv(ConnectMessage())
print(reply)
sessionID = reply.sessionID

# Authentication
reply = send_and_recv(RSAKeyMessage(sessionID))
print(reply)
RSAKey = reply.RSAKey

AESKey = os.urandom(32)
reply = send_and_recv(SessionKeyMessage(sessionID, RSAKey, AESKey))
reply = SessionKeyReply(reply.contenu, AESKey)
print(reply)
salt = reply.salt

reply = send_and_recv(AuthMessage(AESKey, sessionID, salt, IDENTIFIANT, MOT_DE_PASSE))
print(reply)


reply = send_and_recv(GetFilesMessage(AESKey, sessionID, DIRECTORY))
reply = GetFilesReply(AESKey, reply.contenu)
print(reply)

reply = send_and_recv(GetFileMessage(AESKey, sessionID, FILE))
reply = GetFileReply(AESKey, reply.contenu)
print(reply)
```

Flags: `DGA{746999b743b91605261e}`, `DGA{bc3fc7a1a08d5749aa01}` and `DGA{222df851d8a68bda4a85}`.