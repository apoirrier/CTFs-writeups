# Hackllebarde ransomware [2/4]

> Pour la suite de cette investigation, on vous donne accès à un dump mémoire d'une de nos stations qui a été compromise. Vous devez trouver la source de l'infection ! Aussi, il semblerait que le hackeur ait consulté des ressources depuis cette machine. Savoir quelles sont les techniques sur lesquelles il s'est renseigné nous aiderait beaucoup, alors retrouvez cette information !
>
> Vous devez retrouver :
>
> - une adresse IP distante qui a été contactée pour transmettre des données
>
> - un numéro de port de la machine compromise qui a servi à échanger des données
>
> - le nom d'un fichier exécutable malveillant
>
> - un lien web correspondant à la ressource consultée par l'attaquant
>
> Le flag est sous ce format : 404CTF{ip:port:binaire:lien} Par exemple, 404CTF{127.0.0.1:80:bash:https://google.fr/une-ressource-sympa/interessant.html} est un format de flag valide.

## Création du profil volatility

On nous donne un dump mémoire à analyser.

Je décide de l'analyser avec [volatility](https://github.com/volatilityfoundation/volatility) (j'ai tenté d'utiliser `volatility3` mais sans succès, donc comme j'ai l'habitude de la version originale j'ai résolu le challenge avec `python2`).

Pour utiliser volatility, il faut créer un profil qui permette d'analyser le dump mémoire.
Pour ce faire, j'essaie de savoir à quel type de machine j'ai affaire :

```bash
volatility -f dumpmem.raw imageinfo
```

> Suggested Profile(s) : No suggestion

Aucun résultat, et on m'indique qu'il s'agit d'un dump Linux.
Je cherche donc à avoir la bonne version de la distribution et du noyau:

```bash
strings dumpmem.raw | grep -i 'Linux version'
```
> MESSAGE=Linux version 5.4.0-107-generic (buildd@lcy02-amd64-070) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #121~18.04.1-Ubuntu SMP Thu Mar 24 17:21:33 UTC 2022 (Ubuntu 5.4.0-107.121~18.04.1-generic 5.4.174)

Je dois donc créer un profil pour cette version de Linux.

Pour ce faire, je télécharge une image d'Ubuntu 18.04 et je lance la VM.

Je vérifie que le kernel est disponible:

```bash
sudo apt search linux-image | grep 5.4.0-107-generic
```

Puis je l'installe :

```bash
sudo apt install linux-image-5.4.0-107-generic linux-headers-5.4.0-107-generic
sudo reboot
```

Enfin, je crée le profil avec:

```bash
wget https://gist.githubusercontent.com/andreafortuna/98af14f1fa5de2a9e1ce93afbfe24200/raw/8e6e710ec23270f2564e1dd70e8fdfcec1bd1706/volprofile.sh -O volprofile.sh
sudo chmod +x volprofile.sh
./volprofile.sh
```

On peut maintenant copier le profil (.zip) qui vient d'être créé sur la machine d'analyse dans le dossier `volatility/volatility/plugins/overlays/linux/`.

## Analyser le dump mémoire

Je commence par regarder quels processus sont ouverts:

```bash
volatility --plugins=profile -f dumpmem.raw --profile=LinuxUbuntu_5_4_0-107-generic_profilex64 linux_psaux
```

Un extrait de la réponse:

> 2645   1000   1000   /usr/bin/python3 ./JeNeSuisPasDuToutUnFichierMalveillant
>
> 2646   1000   1000   sh -c nc -lvnp 13598 > /tmp/secret
>
> 2647   1000   1000   nc -lvnp 13598
>
> 2662   1000   1000   bash

On a donc le nom du fichier malveillant.

Je cherche ensuite une connection effectuée:

```bash
volatility --plugins=profile -f dumpmem.raw --profile=LinuxUbuntu_5_4_0-107-generic_profilex64 linux_netscan
```

> TCP      192.168.61.2    :13598 192.168.61.137  :38088 ESTABLISHED                    nc/2647

J'ai donc l'IP (192.168.61.137) et le port (38088).

J'ai ensuite passé pas mal de temps à trouver l'URL, en essayant d'extraire `places.sqlite` de Firefox mais sans succès.

J'ai finalement réussi avec une solution simple:

```bash
strings dumpmem.raw | grep https
```

> https://support.google.com/youtube/?p=noaudio
>
> https?:\/\/[^\/]+
>
> https://pki.goog/repository/0
>
> https://pki.goog/repository/0
>
> https://www.youtube.com/watch?v=3Kq1MIfTWCE
>
> ^https?://(\w|-)+\.cdn\.ampproject\.(net|org)(\?|/|$)
>
> https://i.ytimg.com/vi_webp/3Kq1MIfTWCE/maxresdefault.webp
>
> ^https?://(music|music-green-qa|music-release-qa)\.youtube\.com/https://i.ytimg.com/vi/3Kq1MIfTWCE/maxresdefault.jpg
>
> https://www.youtube.com/v/3Kq1MIfTWCE?version=3&autohide=1
>
> https://www.youtube.com/

Ce qui me donne le flag complet.

Flag: `404CTF{192.168.61.137:13598:JeNeSuisPasDuToutUnFichierMalveillant:https://www.youtube.com/watch?v=3Kq1MIfTWCE}`.